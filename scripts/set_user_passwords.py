#!/usr/bin/env python3
"""
Script to set password_hash for existing users to a hash of their username.
Run once after schema changes: python3 scripts/set_user_passwords.py
"""
import os
import sys
# Ensure project root is on sys.path so we can import the backend package
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backend.database import SessionLocal, init_db
from backend.auth import hash_password
from backend.models import User

if __name__ == '__main__':
    init_db()
    db = SessionLocal()
    try:
        users = db.query(User).all()
        for u in users:
            if not u.password_hash:
                u.password_hash = hash_password(u.username)
                print(f"Set password for {u.username} -> (username as password)")
        db.commit()
    finally:
        db.close()
    print('Done.')
