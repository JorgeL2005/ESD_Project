from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import jwt
from jose.exceptions import JWTError
from datetime import datetime, timedelta
from .database import SessionLocal
from .models import User, AuditLog
from .schemas import RegisterRequest, RegisterResponse, LoginRequest, TokenResponse
from .crypto_utils import generate_user_keypair_pem
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


@router.post("/register", response_model=RegisterResponse)
def register(req: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == req.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="El usuario ya existe")

    if req.role not in {"voter", "auditor", "admin"}:
        raise HTTPException(status_code=400, detail="Rol inválido")

    priv_pem, pub_pem = generate_user_keypair_pem()

    user = User(
        username=req.username,
        password_hash=hash_password(req.password),
        role=req.role,
        public_key_pem=pub_pem,
    )
    db.add(user)
    db.flush()
    db.add(AuditLog(user_id=user.id, action="register", ip=request.client.host))
    db.commit()

    return RegisterResponse(message="Usuario registrado. Descargue su clave privada.", private_key_pem=priv_pem, username=user.username, role=user.role)


@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas")

    token = create_access_token({"sub": user.username, "role": user.role})
    db.add(AuditLog(user_id=user.id, action="login", ip=request.client.host))
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