from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from typing import List
from typing import Optional
from datetime import datetime
import os
import base64

from backend.database import init_db, SessionLocal
from .auth import router as auth_router, get_current_user, SECRET_KEY, ALGORITHM
from backend.models import User, Vote, AuditLog, Candidate, BallotToken
from backend.schemas import CandidateOption,VoteRequest, LedgerPage, VoteLedgerItem, ResultSummaryResponse, ResultSummaryItem
from backend.crypto_utils import ensure_system_keys, load_system_public_key_pem, verify_signature, sha256_hex, decrypt_with_system_private, mine_pow, verify_pow
from jose import jwt


app = FastAPI(title="Sistema de Votación Digital Segura")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
def on_startup():
    # Inicializar DB y llaves del sistema
    init_db()
    ensure_system_keys()

    # ---- INSERTAR CANDIDATOS SI LA TABLA ESTÁ VACÍA ----
    #from database import SessionLocal
    #from models import Candidate

    db = SessionLocal()
    try:
        count = db.query(Candidate).count()
        if count == 0:
            initial_candidates = [
                Candidate(name="Candidate A"),
                Candidate(name="Candidate B"),
                Candidate(name="Candidate C")
            ]
            db.add_all(initial_candidates)
            db.commit()
            print("✓ Candidatos iniciales agregados.")
        else:
            print("✓ Candidatos ya existen, no se insertan.")
    finally:
        db.close()

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

@app.get("/candidates", response_model=List[CandidateOption])
def get_candidates(db: Session = Depends(get_db)):
    candidates = db.query(Candidate).all()
    return [CandidateOption(id=c.id, name=c.name) for c in candidates]


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
    # Se admite Authorization (flujo actual) o X-Ballot-Token (flujo anonimizado)
    authorization = request.headers.get("authorization")
    ballot_hdr = request.headers.get("x-ballot-token")

    user_for_logging = None
    public_key_pem_for_verify = None

    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
        current_user = get_current_user(token, db)
        require_role(current_user, {"voter"})
        if current_user.has_voted:
            raise HTTPException(status_code=400, detail="El usuario ya emitió su voto")
        user_for_logging = current_user
        public_key_pem_for_verify = current_user.public_key_pem
    elif ballot_hdr:
        # Validar ballot token (firma y expiración) y buscar BallotToken
        try:
            payload = jwt.decode(ballot_hdr, SECRET_KEY, algorithms=[ALGORITHM])
        except Exception:
            raise HTTPException(status_code=400, detail="Ballot token inválido o expirado")
        if payload.get("typ") != "ballot":
            raise HTTPException(status_code=400, detail="Tipo de token inválido")
        jti = payload.get("jti")
        bt = db.query(BallotToken).filter(BallotToken.jti == jti).first()
        if not bt:
            raise HTTPException(status_code=400, detail="Ballot token no encontrado")
        if bt.used:
            raise HTTPException(status_code=400, detail="Ballot token ya usado")
        if bt.expires_at and bt.expires_at < datetime.utcnow():
            raise HTTPException(status_code=400, detail="Ballot token expirado")
        public_key_pem_for_verify = bt.user_public_key_pem
        user_for_logging = db.query(User).get(bt.user_id)
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Falta Authorization o X-Ballot-Token")

    try:
        ciphertext = base64.b64decode(req.encrypted_vote_b64)
        signature = base64.b64decode(req.signature_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Formato Base64 inválido")

    # Verificar firma sobre el ciphertext para autenticidad
    if not verify_signature(public_key_pem_for_verify, ciphertext, signature):
        raise HTTPException(status_code=400, detail="Firma inválida")

    # Hash del voto (del ciphertext) para el ledger
    vote_hash = sha256_hex(ciphertext)
    last = db.query(Vote).order_by(Vote.id.desc()).first()
    prev_hash = last.vote_hash_hex if last else None
    # Ejecutar PoW (minado) sobre (ciphertext || prev_hash)
    POW_DIFFICULTY = int(os.getenv("POW_DIFFICULTY", "3"))
    pow_input = ciphertext + (prev_hash.encode() if prev_hash else b"")
    try:
        nonce, pow_hash = mine_pow(pow_input, POW_DIFFICULTY)
    except Exception:
        raise HTTPException(status_code=500, detail="Error realizando PoW")

    record = Vote(
        encrypted_vote_b64=req.encrypted_vote_b64,
        signature_b64=req.signature_b64,
        vote_hash_hex=vote_hash,
        prev_hash_hex=prev_hash,
        nonce_int=nonce,
        pow_hash_hex=pow_hash,
    )
    db.add(record)
    if ballot_hdr:
        bt.used = True
        bt.used_at = datetime.utcnow()
        if user_for_logging:
            user_for_logging.has_voted = True
        db.add(AuditLog(user_id=user_for_logging.id if user_for_logging else None, action="vote_submitted_token", ip=request.client.host))
    else:
        if user_for_logging:
            user_for_logging.has_voted = True
        db.add(AuditLog(user_id=user_for_logging.id if user_for_logging else None, action="vote_submitted", ip=request.client.host))
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
        VoteLedgerItem(id=v.id, vote_hash_hex=v.vote_hash_hex, prev_hash_hex=v.prev_hash_hex, timestamp=v.timestamp, nonce=v.nonce_int, pow_hash_hex=v.pow_hash_hex)
        for v in items_q
    ]
    return LedgerPage(items=items, page=page, page_size=page_size, total=total)

from fastapi import APIRouter
from .crypto_utils import sha256_hex, decrypt_with_system_private
import base64

@app.get("/audit/verify-ledger")
def verify_ledger(request: Request, db: Session = Depends(get_db)):
    authorization = request.headers.get("authorization")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token requerido")
    token = authorization.split(" ", 1)[1]
    current_user = get_current_user(token, db)
    require_role(current_user, {"auditor", "admin"})

    votes = db.query(Vote).order_by(Vote.id.asc()).all()

    # Verificación de cadena
    prev_hash = None
    for v in votes:
        computed = sha256_hex(base64.b64decode(v.encrypted_vote_b64))
        if computed != v.vote_hash_hex:
            return {"valid": False, "error": f"Hash incorrecto en voto ID {v.id}"}
        if v.prev_hash_hex != prev_hash:
            return {"valid": False, "error": f"Prev hash incorrecto en voto ID {v.id}"}
        # Verificar PoW si existe
        pow_input = base64.b64decode(v.encrypted_vote_b64) + (v.prev_hash_hex.encode() if v.prev_hash_hex else b"")
        if v.nonce_int is None or v.pow_hash_hex is None:
            return {"valid": False, "error": f"Falta PoW en voto ID {v.id}"}
        if not verify_pow(pow_input, v.nonce_int, int(os.getenv("POW_DIFFICULTY", "3"))):
            return {"valid": False, "error": f"PoW inválido en voto ID {v.id}"}
        # verificar que pow_hash_hex coincide
        nbytes = int(v.nonce_int).to_bytes(8, "big")
        recomputed_pow = sha256_hex(pow_input + nbytes)
        if recomputed_pow != v.pow_hash_hex:
            return {"valid": False, "error": f"PoW hash inconsistente en voto ID {v.id}"}
        prev_hash = v.vote_hash_hex

    return {"valid": True, "message": "La cadena de votos es consistente"}

@app.get("/audit/results")
def audit_results(request: Request, db: Session = Depends(get_db)):
    authorization = request.headers.get("authorization")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token requerido")
    token = authorization.split(" ", 1)[1]
    current_user = get_current_user(token, db)
    require_role(current_user, {"auditor", "admin"})

    votes = db.query(Vote).all()
    counts = {}
    invalid_count = 0

    for v in votes:
        try:
            plaintext = decrypt_with_system_private(base64.b64decode(v.encrypted_vote_b64)).decode()
        except Exception:
            # Omitir votos no descifrables de la distribución; contabilizar para auditoría
            invalid_count += 1
            continue

        counts[plaintext] = counts.get(plaintext, 0) + 1

    return {"counts": counts, "invalid_count": invalid_count}

@app.get("/results/summary", response_model=ResultSummaryResponse)
def results_summary(request: Request, db: Session = Depends(get_db)):
    authorization = request.headers.get("authorization")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token requerido")
    token = authorization.split(" ", 1)[1]
    current_user = get_current_user(token, db)
    require_role(current_user, {"auditor", "admin"})

    votes = db.query(Vote).all()
    counts: dict[str, int] = {}
    for v in votes:
        try:
            plaintext = decrypt_with_system_private(base64.b64decode(v.encrypted_vote_b64)).decode()
        except Exception:
            # Omitir votos no descifrables del resumen
            continue
        counts[plaintext] = counts.get(plaintext, 0) + 1

    total = sum(counts.values())
    results = []
    for cand, cnt in counts.items():
        perc = (cnt / total * 100.0) if total else 0.0
        results.append(ResultSummaryItem(candidate=cand, vote_count=cnt, percentage=round(perc, 3)))
    return ResultSummaryResponse(total_votes=total, results=results)




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
            "nonce": v.nonce_int,
            "pow_hash_hex": v.pow_hash_hex,
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
