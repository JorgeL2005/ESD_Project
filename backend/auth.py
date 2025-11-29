from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import jwt
from jose.exceptions import JWTError
from datetime import datetime, timedelta
from .database import SessionLocal
from .models import User, AuditLog, LoginChallenge
from .schemas import RegisterRequest, RegisterResponse, LoginRequest, TokenResponse, BallotIssueResponse
from .models import BallotToken
from .crypto_utils import generate_user_keypair_pem, verify_signature
import os


router = APIRouter(prefix="/auth", tags=["auth"])

# Usamos PBKDF2-SHA256 para evitar la limitación de 72 bytes de bcrypt y
# el problema de compatibilidad observado (AttributeError en bcrypt.__about__).
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto",
    pbkdf2_sha256__rounds=310000,
)

SECRET_DIR = os.path.join(os.getcwd(), "secrets")
os.makedirs(SECRET_DIR, exist_ok=True)
SECRET_FILE = os.path.join(SECRET_DIR, "jwt_secret.txt")

if not os.path.exists(SECRET_FILE):
    with open(SECRET_FILE, "w", encoding="utf-8") as f:
        f.write(os.urandom(32).hex())

with open(SECRET_FILE, "r", encoding="utf-8") as f:
    SECRET_KEY = f.read().strip()

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8
BALLOT_TOKEN_EXPIRE_MINUTES = 30


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_ballot_token(jti: str, expires_minutes: int = BALLOT_TOKEN_EXPIRE_MINUTES):
    payload = {
        "jti": jti,
        "typ": "ballot",
        "exp": datetime.utcnow() + timedelta(minutes=expires_minutes),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


@router.post("/register", response_model=RegisterResponse)
def register(req: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    # Registro restringido: sólo administradores (municipalidad) pueden crear cuentas
    authorization = request.headers.get("authorization")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token requerido para registrar usuarios")
    token = authorization.split(" ", 1)[1]
    try:
        admin_user = get_current_user(token, db)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
    if admin_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Solo administradores pueden registrar usuarios")

    existing = db.query(User).filter(User.username == req.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="El usuario ya existe")

    if req.role not in {"voter", "auditor", "admin"}:
        raise HTTPException(status_code=400, detail="Rol inválido")

    priv_pem, pub_pem = generate_user_keypair_pem()

    # Password is required for registration
    if not getattr(req, 'password', None):
        raise HTTPException(status_code=400, detail="Password es requerida para crear el usuario")
    pwd_hash = hash_password(req.password)

    user = User(
        username=req.username,
        password_hash=pwd_hash,
        role=req.role,
        public_key_pem=pub_pem,
    )
    db.add(user)
    db.flush()
    db.add(AuditLog(user_id=admin_user.id, action=f"register_user:{user.username}", ip=request.client.host))
    db.commit()

    return RegisterResponse(message="Usuario registrado. Descargue su clave privada.", private_key_pem=priv_pem, username=user.username, role=user.role)


@router.post('/login', response_model=TokenResponse)
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user:
        raise HTTPException(status_code=404, detail='Usuario no encontrado')
    if not user.password_hash:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Password no configurada')
    if not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Password inválida')

    token = create_access_token({"sub": user.username, "role": user.role})
    db.add(AuditLog(user_id=user.id, action='login_password', ip=request.client.host))
    db.commit()
    return TokenResponse(access_token=token)


@router.get("/challenge")
def get_challenge(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    # generar reto aleatorio y persistir
    j = os.urandom(16)
    challenge_b64 = (j).hex()
    expires_at = datetime.utcnow() + timedelta(minutes=5)
    lc = LoginChallenge(username=username, challenge_b64=challenge_b64, expires_at=expires_at)
    db.add(lc)
    db.commit()
    return {"challenge_b64": challenge_b64, "expires_at": expires_at}


@router.post("/login-sig", response_model=TokenResponse)
def login_sig(payload: dict, request: Request, db: Session = Depends(get_db)):
    username = payload.get("username")
    signature_b64 = payload.get("signature_b64")
    if not username or not signature_b64:
        raise HTTPException(status_code=400, detail="Faltan parámetros")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    # recuperar reto válido
    lc = db.query(LoginChallenge).filter(LoginChallenge.username == username).order_by(LoginChallenge.id.desc()).first()
    if not lc or lc.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Reto no encontrado o expirado")

    try:
        sig = bytes.fromhex(signature_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Firma en formato inválido (usar hex)")

    challenge_bytes = bytes.fromhex(lc.challenge_b64)
    if not verify_signature(user.public_key_pem, challenge_bytes, sig):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Firma inválida")

    token = create_access_token({"sub": user.username, "role": user.role})
    db.add(AuditLog(user_id=user.id, action="login_sig", ip=request.client.host))
    db.commit()
    return TokenResponse(access_token=token)


def get_current_user(token: str, db: Session) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido", headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user


@router.get("/me")
def me(request: Request, db: Session = Depends(get_db)):
    authorization = request.headers.get("authorization")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token requerido")
    token = authorization.split(" ", 1)[1]
    user = get_current_user(token, db)
    return {"username": user.username, "role": user.role}

@router.post("/issue-ballot", response_model=BallotIssueResponse)
def issue_ballot(request: Request, db: Session = Depends(get_db)):
    authorization = request.headers.get("authorization")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token requerido")
    token = authorization.split(" ", 1)[1]
    user = get_current_user(token, db)
    if user.role != "voter":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Solo votantes pueden solicitar boleta")
    if user.has_voted:
        raise HTTPException(status_code=400, detail="El usuario ya emitió su voto")

    # Generar jti aleatorio y token de boleta
    jti = os.urandom(16).hex()
    expires_at = datetime.utcnow() + timedelta(minutes=BALLOT_TOKEN_EXPIRE_MINUTES)
    ballot_jwt = create_ballot_token(jti)

    # Persistir BallotToken (incluye la clave pública para verificación sin cargar el usuario)
    bt = BallotToken(
        jti=jti,
        user_id=user.id,
        user_public_key_pem=user.public_key_pem,
        expires_at=expires_at,
    )
    db.add(bt)
    db.add(AuditLog(user_id=user.id, action="ballot_issued", ip=request.client.host))
    db.commit()

    return BallotIssueResponse(ballot_token=ballot_jwt, jti=jti, expires_at=expires_at)


@router.post('/save-credential', response_class=HTMLResponse)
async def save_credential(request: Request):
    # Endpoint mínimo para permitir un POST de formulario que algunos navegadores
    # reconocen como un inicio de sesión y por eso pueden ofrecer guardar la credencial.
    # No almacenamos nada: solo devolvemos una página sencilla para cerrar la pestaña.
    try:
        form = await request.form()
        username = form.get('username', '')
    except Exception:
        username = ''
    html = f"""
    <!doctype html>
    <html lang="es">
    <head><meta charset="utf-8"><title>Guardar credencial</title></head>
    <body>
      <p>Se intentó guardar la credencial para: <strong>{username}</strong>.</p>
      <p>Si el navegador ofreció guardar, confirme la operación. Puede cerrar esta pestaña.</p>
    </body>
    </html>
    """
    return HTMLResponse(content=html)
