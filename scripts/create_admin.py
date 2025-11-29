#!/usr/bin/env python3
"""Script simple para crear un usuario admin y obtener su clave privada PEM.

Uso:
  python3 scripts/create_admin.py --username municipal_admin

El script:
 - llama a `init_db()` para asegurarse de que las tablas existen
 - genera un par de claves RSA (priv/pub)
 - inserta el usuario en la tabla `users` con `role='admin'` y `public_key_pem`
 - escribe la clave privada en `keys/{username}_private.pem` y la imprime por stdout

Nota: Ejecútalo en el entorno del proyecto con las dependencias instaladas.
"""
import os
import argparse
import getpass
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import sys
sys.path.insert(0, PROJECT_ROOT)

from backend.database import init_db, SessionLocal
from backend.crypto_utils import generate_user_keypair_pem
from backend.models import User, AuditLog
from backend.auth import hash_password


def create_admin(username: str):
    init_db()
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            print(f"Error: el usuario '{username}' ya existe (id={existing.id}).")
            return 1

        priv_pem, pub_pem = generate_user_keypair_pem()

        # Prompt for password (required)
        while True:
            pwd = getpass.getpass(f"Password for new admin '{username}': ")
            if not pwd:
                print('Password no puede estar vacía. Intente de nuevo.')
                continue
            pwd2 = getpass.getpass('Confirmar password: ')
            if pwd != pwd2:
                print('Las contraseñas no coinciden. Intente de nuevo.')
                continue
            break

        pwd_hash = hash_password(pwd)

        user = User(
            username=username,
            password_hash=pwd_hash,
            role="admin",
            public_key_pem=pub_pem,
        )
        db.add(user)
        db.flush()
        db.add(AuditLog(user_id=user.id, action=f"create_admin_script", ip="127.0.0.1"))
        db.commit()

        keys_dir = os.path.join(PROJECT_ROOT, "keys")
        os.makedirs(keys_dir, exist_ok=True)
        # Save private key as .txt (easier to open on various platforms)
        priv_path = os.path.join(keys_dir, f"{username}_private.txt")
        with open(priv_path, "w", encoding="utf-8") as f:
            f.write(priv_pem)

        print("Administrador creado correctamente:")
        print(f"  username: {username}")
        print(f"  id: {user.id}")
        print("")
        print("Clave privada PEM (guárdala y entrégala en persona):")
        print("--- BEGIN PRIVATE KEY ---")
        print(priv_pem)
        print("--- END PRIVATE KEY ---")
        print("")
        print(f"También guardada en: {priv_path}")
        return 0
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description="Crear usuario admin y generar clave privada PEM")
    parser.add_argument("--username", required=True, help="Nombre de usuario para el admin a crear")
    args = parser.parse_args()

    code = create_admin(args.username)
    sys.exit(code)


if __name__ == '__main__':
    main()
