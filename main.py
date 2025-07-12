# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path


from app.api.auth import router as auth_router
from app.api.csv_api import router as csv_router
from app.core import settings
from app.core.security import manager
from app.db.db import SessionLocal, engine, Base, init_db
from app.db.models import User
from app.services.auth_service import get_password_hash
from app.core.csrf import CSRFMiddleware

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
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
# CSRF protection middleware / CSRF-Schutz Middleware hinzufügen
app.add_middleware(CSRFMiddleware, secret_key=settings.SECRET_KEY)

# Set up paths / Pfade einrichten
BASE_DIR = Path(__file__).resolve().parent
APP_DIR = BASE_DIR / "app"
STATIC_DIR = APP_DIR / "static"
TEMPLATES_DIR = APP_DIR / "templates"

# Mount static files / Statische Dateien mounten
app.mount(
    "/static",
    StaticFiles(directory=str(STATIC_DIR)),
    name="static"
)

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

# Root route redirects to login / Root-Route leitet zu Login um
@app.get("/")
async def root():
    return RedirectResponse(url="/auth/login")

# Start the app with: uvicorn main:app --reload