# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

from fastapi import APIRouter, Form, Request, Depends, HTTPException, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from datetime import timedelta
from pathlib import Path

from app.services.auth_service import authenticate_user, create_user
from app.db.models import User
from app.core import settings
from app.core.security import manager
import secrets

# Set up templates / Templates einrichten
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Auth router for login functionality / Auth-Router für Login-Funktionalität
router = APIRouter(prefix="", tags=["auth"])

# Get access token expire minutes from settings / Zugriffstoken-Expire-Minuten aus Einstellungen abrufen
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES

@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    # Show login form / Login-Formular anzeigen
    token = secrets.token_urlsafe(32)
    response = templates.TemplateResponse("login.html", {"request": request, "error": None, "csrf_token": token})
    response.set_cookie(key="csrf_token", value=token, httponly=False)
    return response

@router.post("/login")
async def login(request: Request, username: str = Form(None), password: str = Form(None), csrf_token: str = Form(None), csrf_token_cookie: str = Cookie(None, alias="csrf_token")):
    # Handle login for HTML form and JSON requests / Login für HTML-Formular und JSON-Anfragen verarbeiten
    # JSON login / JSON Login
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("application/json"):
        data = await request.json()
        username = data.get("username")
        password = data.get("password")
        # Authenticate user / Benutzer authentifizieren
        user = authenticate_user(username, password)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        access_token = manager.create_access_token(
            data={"sub": user.username},
            expires=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        json_response = JSONResponse({"access_token": access_token})
        manager.set_cookie(json_response, access_token)
        return json_response

    # Process login / Login verarbeiten
    # CSRF protection / CSRF-Schutz
    if not csrf_token or csrf_token != csrf_token_cookie:
        token = secrets.token_urlsafe(32)
        response = templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Ungültiges CSRF-Token", "csrf_token": token},
            status_code=403
        )
        response.set_cookie(key="csrf_token", value=token, httponly=False)
        return response

    # Authenticate user / Benutzer authentifizieren
    user = authenticate_user(username, password)
    if not user:
        token = secrets.token_urlsafe(32)
        response = templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid credentials / Ungültige Zugangsdaten", "csrf_token": token},
            status_code=401
        )
        response.set_cookie(key="csrf_token", value=token, httponly=False)
        return response

    # Create access token / Zugriffstoken erstellen
    access_token = manager.create_access_token(
        data={"sub": user.username},
        expires=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    response = RedirectResponse(url="/", status_code=303)
    manager.set_cookie(response, access_token)
    return response

@router.get("/logout")
async def logout():
    response = RedirectResponse(url="/auth/login")
    response.delete_cookie(key=manager.cookie_name)
    return response
