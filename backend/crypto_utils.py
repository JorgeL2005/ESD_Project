from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import os


KEYS_DIR = os.path.join(os.getcwd(), "keys")
CERTS_DIR = os.path.join(os.getcwd(), "certs")
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(CERTS_DIR, exist_ok=True)

SYSTEM_PRIV = os.path.join(KEYS_DIR, "system_private.pem")
SYSTEM_PUB = os.path.join(KEYS_DIR, "system_public.pem")


def sha256_hex(data: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()


def ensure_system_keys():
    if os.path.exists(SYSTEM_PRIV) and os.path.exists(SYSTEM_PUB):
        return
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(SYSTEM_PRIV, "wb") as f:
        f.write(priv_pem)
    with open(SYSTEM_PUB, "wb") as f:
        f.write(pub_pem)


def load_system_private_key():
    ensure_system_keys()
    with open(SYSTEM_PRIV, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_system_public_key_pem() -> str:
    ensure_system_keys()
    with open(SYSTEM_PUB, "r", encoding="utf-8") as f:
        return f.read()


def generate_user_keypair_pem() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def verify_signature(public_key_pem: str, message: bytes, signature: bytes) -> bool:
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def decrypt_with_system_private(ciphertext: bytes) -> bytes:
    private_key = load_system_private_key()
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def ensure_self_signed_cert():
    cert_file = os.path.join(CERTS_DIR, "server.crt")
    key_file = os.path.join(CERTS_DIR, "server.key")
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return cert_file, key_file

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Lima"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lima"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Proyecto Votacion Segura"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )

    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    with open(key_file, "wb") as f:
        f.write(priv_pem)
    with open(cert_file, "wb") as f:
        f.write(cert_pem)

    return cert_file, key_file