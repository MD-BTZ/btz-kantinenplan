# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

from fastapi import Depends, HTTPException, status, Request
from fastapi_login import LoginManager
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
from .settings import Settings
from jose import JWTError, jwt

# Create settings instance / Settings-Instanz erstellen
settings = Settings()

# Initialize LoginManager / LoginManager initialisieren
manager = LoginManager(
    secret=settings.SECRET_KEY,
    token_url="/auth/login",
    use_cookie=True
)
# tighten cookie flags for production safety / Produktionssicherheit: Cookie-Flags verstärken
manager.cookie_secure = settings.COOKIE_SECURE
manager.cookie_samesite = settings.COOKIE_SAMESITE
manager.cookie_httponly = settings.COOKIE_HTTPONLY

@manager.user_loader()
def load_user(username: str):
    from app.db.db import SessionLocal
    from app.db.models import User
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        return user
    finally:
        db.close()

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = "HS256"

# Create access token with additional claims / Zugriffstoken mit zusätzlichen Ansprüchen erstellen
class TokenData:
    username: str | None = None

# Function to create access token / Funktion, um Zugriffstoken zu erstellen
async def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

# Create refresh token with additional claims / Funktion, um Aktualisierungstoken zu erstellen
async def create_refresh_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.REFRESH_SECRET, algorithm=settings.ALGORITHM)
    return encoded_jwt

# Verify refresh token / Funktion, um Aktualisierungstoken zu überprüfen
async def verify_refresh_token(token: str):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        return username
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

# Dependency to get current user from cookie / Abhängigkeit, um aktuelle Benutzerinformationen aus dem Cookie abzurufen
async def get_current_user(request: Request):
    token = request.cookies.get(manager.cookie_name)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Not authenticated"
        )

    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    user = load_user(username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="User not found"
        )
    
    return user
