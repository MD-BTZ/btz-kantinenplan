# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

from sqlalchemy.orm import Session
from passlib.context import CryptContext
from db import User, SessionLocal

# Password hashing context (bcrypt) / Passwort-Hashing-Kontext (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    # Hash a password using bcrypt / Passwort mit bcrypt hashen
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Verify a password against its hash / Passwort gegen Hash prüfen
    return pwd_context.verify(plain_password, hashed_password)

def create_user(username: str, password: str) -> User:
    # Create a new user with hashed password / Neuen Benutzer mit gehashtem Passwort anlegen
    db: Session = SessionLocal()
    try:
        user = User(username=username, password_hash=get_password_hash(password))
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()

def authenticate_user(username: str, password: str) -> User:
    # Authenticate user by username and password / Benutzer anhand von Benutzername und Passwort authentifizieren
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if user and verify_password(password, user.password_hash):
            return user
        return None
    finally:
        db.close()
