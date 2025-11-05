from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from typing import Optional
import os
import base64

from .database import init_db, SessionLocal
from .auth import router as auth_router, get_current_user
from .models import User, Vote, AuditLog
from .schemas import VoteRequest, LedgerPage, VoteLedgerItem
from .crypto_utils import ensure_system_keys, load_system_public_key_pem, verify_signature, sha256_hex, decrypt_with_system_private


app = FastAPI(title="Sistema de Votación Digital Segura")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
def on_startup():
    init_db()
    ensure_system_keys()
    # Servir frontend
    frontend_dir = os.path.join(os.getcwd(), "frontend")
    if os.path.isdir(frontend_dir):
        app.mount("/static", StaticFiles(directory=frontend_dir), name="static")


@app.get("/")
def root():
    index_path = os.path.join(os.getcwd(), "frontend", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "API activa"}


app.include_router(auth_router)


@app.get("/keys/system-public")
def get_system_public_key():
    return {"public_key_pem": load_system_public_key_pem()}


def require_role(user: User, roles: set[str]):
    if user.role not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Rol no autorizado")


@app.post("/vote")
def submit_vote(
    req: VoteRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    # Obtener token
    authorization = request.headers.get("authorization")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token requerido")
    token = authorization.split(" ", 1)[1]
    current_user = get_current_user(token, db)
    require_role(current_user, {"voter"})

    if current_user.has_voted:
        raise HTTPException(status_code=400, detail="El usuario ya emitió su voto")

    try:
        ciphertext = base64.b64decode(req.encrypted_vote_b64)
        signature = base64.b64decode(req.signature_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Formato Base64 inválido")

    # Verificar firma sobre el ciphertext para autenticidad
    if not verify_signature(current_user.public_key_pem, ciphertext, signature):
        raise HTTPException(status_code=400, detail="Firma inválida")

    # Hash del voto (del ciphertext) para el ledger
    vote_hash = sha256_hex(ciphertext)
    last = db.query(Vote).order_by(Vote.id.desc()).first()
    prev_hash = last.vote_hash_hex if last else None

    record = Vote(
        encrypted_vote_b64=req.encrypted_vote_b64,
        signature_b64=req.signature_b64,
        vote_hash_hex=vote_hash,
        prev_hash_hex=prev_hash,
    )
    db.add(record)
    current_user.has_voted = True
    db.add(AuditLog(user_id=current_user.id, action="vote_submitted", ip=request.client.host))
    db.commit()

    return {"message": "Voto registrado", "vote_hash_hex": vote_hash}


@app.get("/ledger", response_model=LedgerPage)
def ledger(page: int = 1, page_size: int = 10, request: Request = None, db: Session = Depends(get_db)):
    # Sólo auditor/admin pueden ver el ledger
    authorization = request.headers.get("authorization") if request else None
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token requerido")
    token = authorization.split(" ", 1)[1]
    current_user = get_current_user(token, db)
    require_role(current_user, {"auditor", "admin"})

    total = db.query(Vote).count()
    items_q = (
        db.query(Vote).order_by(Vote.id.asc()).offset((page - 1) * page_size).limit(page_size).all()
    )
    items = [
        VoteLedgerItem(id=v.id, vote_hash_hex=v.vote_hash_hex, prev_hash_hex=v.prev_hash_hex, timestamp=v.timestamp)
        for v in items_q
    ]
    return LedgerPage(items=items, page=page, page_size=page_size, total=total)


@app.get("/admin/results")
def admin_results(request: Request, db: Session = Depends(get_db)):
    authorization = request.headers.get("authorization")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token requerido")
    token = authorization.split(" ", 1)[1]
    current_user = get_current_user(token, db)
    require_role(current_user, {"admin"})

    votes = db.query(Vote).order_by(Vote.id.asc()).all()
    results: list[dict] = []
    for v in votes:
        try:
            plaintext = decrypt_with_system_private(base64.b64decode(v.encrypted_vote_b64)).decode(errors="ignore")
        except Exception:
            plaintext = "<no descifrable>"
        results.append({
            "id": v.id,
            "vote_hash_hex": v.vote_hash_hex,
            "plaintext": plaintext,
            "timestamp": v.timestamp.isoformat(),
        })
    return {"results": results}


from .schemas import AuditLogItem, AuditLogPage, SQLQuery, SQLResult
from sqlalchemy import text
from .database import engine


@app.get("/admin/logs", response_model=AuditLogPage)
def admin_logs(page: int = 1, page_size: int = 10, request: Request = None, db: Session = Depends(get_db)):
    authorization = request.headers.get("authorization") if request else None
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token requerido")
    token = authorization.split(" ", 1)[1]
    current_user = get_current_user(token, db)
    require_role(current_user, {"admin"})

    total = db.query(AuditLog).count()
    items_q = db.query(AuditLog).order_by(AuditLog.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    items = [
        AuditLogItem(id=lg.id, username=db.query(User).get(lg.user_id).username if lg.user_id else None, action=lg.action, ip=lg.ip, timestamp=lg.timestamp)
        for lg in items_q
    ]
    return AuditLogPage(items=items, page=page, page_size=page_size, total=total)


def _is_safe_select(query: str) -> bool:
    q = query.strip().lower()
    if not q.startswith("select "):
        return False
    forbidden = [";", "--", " drop ", " delete ", " update ", " insert ", " alter ", " create ", " pragma ", " attach ", " detach "]
    return not any(x in q for x in forbidden)


@app.post("/admin/sql", response_model=SQLResult)
def admin_sql(req: SQLQuery, request: Request, db: Session = Depends(get_db)):
    authorization = request.headers.get("authorization")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token requerido")
    token = authorization.split(" ", 1)[1]
    current_user = get_current_user(token, db)
    require_role(current_user, {"admin"})

    if not _is_safe_select(req.query):
        raise HTTPException(status_code=400, detail="Solo se permiten consultas SELECT sencillas")

    with engine.connect() as conn:
        result = conn.execute(text(req.query))
        cols = list(result.keys())
        rows = [list(row) for row in result.fetchall()[:200]]
    return SQLResult(columns=cols, rows=rows)