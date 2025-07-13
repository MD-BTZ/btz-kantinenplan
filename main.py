# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

from fastapi import FastAPI, Depends, Request, Response, HTTPException, status
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from jose import jwt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.api.auth import router as auth_router, get_current_user
from app.api.csv_api import router as csv_router
from app.core import settings
from app.core.security import manager
from app.db.db import SessionLocal, engine, Base, init_db
from app.db.models import User
from app.services.auth_service import get_password_hash
from app.core.csrf import CSRFMiddleware
from app.core.auth_middleware import AuthMiddleware
from app.core.version import __version__

Base.metadata.create_all(bind=engine)
init_db()  # Initialize database / Datenbank initialisieren

def create_default_user():
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == settings.FIRST_SUPERUSER).first()
        if not admin:
            hashed_password = get_password_hash(settings.FIRST_SUPERUSER_PASSWORD)
            admin = User(
                username=settings.FIRST_SUPERUSER,
                password_hash=hashed_password,
                is_superuser=True
            )
            db.add(admin)
            db.commit()
            print(f"Created default admin user: {settings.FIRST_SUPERUSER}")
    except Exception as e:
        print(f"Error creating default user: {e}")
        db.rollback()
        raise
    finally:
        db.close()


# Create FastAPI app instance / FastAPI-App-Instanz erstellen
app = FastAPI(
    title=settings.PROJECT_NAME,
    debug=settings.DEBUG,
    openapi_url=f"/openapi.json"
)

# Add middleware / Middleware hinzufügen
app.add_middleware(AuthMiddleware)
app.add_middleware(CSRFMiddleware, secret_key=settings.SECRET_KEY)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Set up paths / Pfade einrichten
BASE_DIR = Path(__file__).resolve().parent
APP_DIR = BASE_DIR / "app"
STATIC_DIR = APP_DIR / "static"
TEMPLATES_DIR = APP_DIR / "templates"

# Ensure static directory exists / Statische Verzeichnisstruktur erstellen
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR), html=False), name="static")
else:
    print(f"⚠️ Static directory {STATIC_DIR} does not exist – skipping mount")

# Set up Jinja2 templates / Jinja2-Templates einrichten
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# User loader for fastapi-login / User loader für fastapi-login
@manager.user_loader()
def get_user(username: str):
    db = SessionLocal()
    try:
        return db.query(User).filter(User.username == username).first()
    finally:
        db.close()

# Include routers / Router einbinden
app.include_router(auth_router, prefix="/auth")

app.include_router(csv_router, prefix="/api")

# Create default admin user on startup / Default-Admin-Benutzer bei Start erstellen
@app.on_event("startup")
def on_startup():
    create_default_user()

@app.get("/index", response_class=HTMLResponse)
async def index(request: Request):
    user = None
    # Try to obtain JWT from cookie first, then from Authorization header
    token = request.cookies.get("access-token")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1]
    if token:
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            username: str = payload.get("sub")
            if username is not None:
                user = {"username": username}
        except jwt.JWTError:
            pass
    
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return templates.TemplateResponse("index.html", {"request": request, "user": user, "version": __version__})

# Root route redirects to login / Root-Route leitet zu Login um
@app.get("/")
async def root():
    return RedirectResponse(url="/auth/login")

# Start the app with: uvicorn main:app --reload