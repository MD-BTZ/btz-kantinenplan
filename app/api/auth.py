# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

from fastapi import APIRouter, Form, Request, Depends, HTTPException, Cookie, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi import Body

from datetime import datetime, timedelta
from pathlib import Path
import os

from app.services.auth_service import authenticate_user, create_user
from app.db.models import User
from app.core import settings
from app.core.security import manager, create_access_token, create_refresh_token, verify_refresh_token
import secrets
from bcrypt import hashpw, gensalt, checkpw
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from typing import Optional
from app.core.version import __version__

# Set up templates / Templates einrichten
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Auth router for login functionality / Auth-Router für Login-Funktionalität
router = APIRouter(prefix="", tags=["auth"])

# Get access token expire minutes from settings / Zugriffstoken-Expire-Minuten aus Einstellungen abrufen
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES

# OAuth2 scheme for password authentication / OAuth2-Schema für Passwort-Authentifizierung
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

async def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

async def verify_refresh_token(refresh_token: str):
    try:
        payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        return username
    except JWTError:
        return None

from fastapi import Request as FastAPIRequest

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    # Assume user is valid if username is in token, no password check needed / Nutzer wird als gültig angenommen, wenn der Benutzername im Token enthalten ist, keine Passwortprüfung notwendig
    return {"username": username}

@router.get("/login", response_class=HTMLResponse)
async def get_login(request: Request):
    # Check if user is already authenticated
    if "access-token" in request.cookies:
        try:
            # Verify the access token
            token = request.cookies.get("access-token")
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            if payload:
                # Redirect to /index if the token is valid
                return RedirectResponse(url="/index", status_code=status.HTTP_303_SEE_OTHER)
        except jwt.ExpiredSignatureError:
            pass
        except jwt.InvalidTokenError:
            pass
    # Generate a new CSRF token for the login form
    csrf_token = secrets.token_urlsafe(32)
    response = templates.TemplateResponse("login.html", {"request": request, "version": __version__, "csrf_token": csrf_token})
    response.set_cookie(key="csrf_token", value=csrf_token, httponly=False)
    return response

@router.post("/login")
async def login(request: Request):
    form_data = await request.form()
    csrf_token_cookie = request.cookies.get("csrf_token")
    csrf_token_form = form_data.get("csrf_token")
    if csrf_token_cookie != csrf_token_form:
        if os.getenv("ENV") == "test":
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "CSRF token mismatch"}
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token mismatch"
        )
    # Authenticate user
    username = form_data.get("username")
    password = form_data.get("password")
    if not username or not password:
        if os.getenv("ENV") == "test":
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "Username and password are required"}
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and password are required"
        )
    user = authenticate_user(username, password)
    if not user:
        if os.getenv("ENV") == "test":
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Incorrect username or password"}
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await create_access_token({"sub": user.username}, expires_delta=access_token_expires)
    refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token = await create_refresh_token({"sub": user.username, "refresh": True}, expires_delta=refresh_token_expires)
    response = RedirectResponse(url="/index", status_code=status.HTTP_303_SEE_OTHER)
    # Set both cookie name variants for compatibility with tests
    response.set_cookie(key="access-token", value=access_token, httponly=True)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    response.set_cookie(key="refresh-token", value=refresh_token, httponly=True)
    # Renew CSRF token after login
    new_csrf_token = secrets.token_urlsafe(32)
    response.set_cookie(key="csrf_token", value=new_csrf_token, httponly=False)
    return response

@router.post("/refresh")
async def refresh_token(request: Request, response: Response, refresh_token: str = Cookie(None, alias="refresh-token")):
    csrf_token_header = request.headers.get("X-CSRF-Token")
    csrf_token_cookie = request.cookies.get("csrf_token")

    # Allow fallback to alternative cookie name
    if not refresh_token:
        refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # Validate CSRF token
    if csrf_token_header != csrf_token_cookie:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token mismatch")

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # `verify_refresh_token` returns the username if the token is valid.
        username: str = await verify_refresh_token(refresh_token)
        if not username:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    new_access_token = await create_access_token({"sub": username})
    response.set_cookie(key="access-token", value=new_access_token, httponly=True)
    response.set_cookie(key="access_token", value=new_access_token, httponly=True)
    return {"access_token": new_access_token, "token_type": "bearer"}

@router.get("/logout")
async def logout():
    response = RedirectResponse(url="/auth/login")
    response.delete_cookie(key=manager.cookie_name)
    return response

@router.post("/register")
async def register(request: Request, data: dict = Body(...)):
    # Register a new user via JSON / Neuen Benutzer über JSON registrieren
    try:
        hashed_password = hashpw(data.get("password").encode('utf-8'), gensalt())
        user = create_user(
            data.get("username"),
            hashed_password,
            data.get("is_superuser", False)
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return JSONResponse({"username": user.username}, status_code=201)
