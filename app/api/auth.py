# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

from fastapi import APIRouter, Form, Request, Depends, HTTPException, Cookie, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi import Body

from datetime import datetime, timedelta
from pathlib import Path

from app.services.auth_service import authenticate_user, create_user
from app.db.models import User
from app.core import settings
from app.core.security import manager, create_access_token, create_refresh_token, verify_refresh_token
import secrets
from bcrypt import hashpw, gensalt, checkpw
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from typing import Optional

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

@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    # Show login form / Login-Formular anzeigen
    token = secrets.token_urlsafe(32)
    response = templates.TemplateResponse("login.html", {"request": request, "error": None, "csrf_token": token})
    response.set_cookie(key="csrf_token", value=token, httponly=False)
    return response

@router.post("/login")
async def login(request: Request, username: str = Form(None), password: str = Form(None), csrf_token: str = Form(None), csrf_token_cookie: str = Cookie(None, alias="csrf_token")):
    # Log incoming request details
    print(f"Login request received: username={username}, csrf_token={csrf_token}, csrf_token_cookie={csrf_token_cookie}")

    # Handle login for HTML form and JSON requests / Login für HTML-Formular und JSON-Anfragen verarbeiten
    # JSON login / JSON Login
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("application/json"):
        data = await request.json()
        username = data.get("username")
        password = data.get("password")
        # Authenticate user with username and password
        user = authenticate_user(username, password)
        if not user:
            print("Authentication failed: Incorrect username or password")
            raise HTTPException(
                status_code=401,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Create access token / Zugriffstoken erstellen
        access_token = await create_access_token(
            data={"sub": user.username},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        # Create refresh token / Refresh-Token erstellen
        refresh_token = await create_refresh_token(
            data={"sub": user.username},
            expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        )
        token = secrets.token_urlsafe(32)
        response = JSONResponse(
            content={"access_token": access_token, "token_type": "bearer", "csrf_token": token},
            status_code=200
        )
        # Set access token as HTTPOnly cookie
        response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="Lax")
        response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=True, samesite="Lax")
        response.set_cookie(key="csrf_token", value=token, httponly=False)
        print("Login successful: Tokens set in cookies")
        return response

    # Form login / Formular-Login
    if not username or not password:
        error = "Bitte Benutzername und Passwort eingeben."
        print("Login failed: Missing username or password")
        return templates.TemplateResponse("login.html", {"request": request, "error": error, "csrf_token": csrf_token_cookie if csrf_token_cookie else secrets.token_urlsafe(32)})

    # Validate CSRF token / CSRF-Token validieren
    if not csrf_token or not csrf_token_cookie or csrf_token != csrf_token_cookie:
        print("CSRF validation failed: Token mismatch")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token mismatch"
        )

    # Authenticate user with username and password / Benutzer mit Benutzername und Passwort authentifizieren
    user = authenticate_user(username, password)
    if not user:
        print("Authentication failed: Incorrect username or password")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    # Create access token using the manager / Zugriffstoken mit Manager erstellen
    access_token = manager.create_access_token(
        data={"sub": user.username},
        expires=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    # Create refresh token / Refresh-Token erstellen
    refresh_token = await create_refresh_token(
        data={"sub": user.username},
        expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    response = RedirectResponse(url="/", status_code=303)
    manager.set_cookie(response, access_token)
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=True, samesite="Lax")
    response.set_cookie(key="csrf_token", value=secrets.token_urlsafe(32), httponly=False)
    print("Login successful: Tokens set in cookies")
    return response

@router.post("/refresh")
async def refresh_token(response: Response, refresh_token: str = Cookie(None)):
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No refresh token provided or invalid")

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = await verify_refresh_token(refresh_token)
        if not payload:
            raise credentials_exception
        username: str = payload.get("sub")
    except JWTError:
        raise credentials_exception
    except AttributeError:
        raise credentials_exception

    new_access_token = manager.create_access_token(data={"sub": username})
    manager.set_cookie(response, new_access_token)
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
