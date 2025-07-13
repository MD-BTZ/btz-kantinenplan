# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

from pydantic_settings import BaseSettings
from typing import List
from dotenv import load_dotenv
import os

# Load environment variables from .env file (if available) / Lade Umgebungsvariablen aus .env-Datei (falls vorhanden)
load_dotenv()

class Settings(BaseSettings):
    # Project name / Projektname
    PROJECT_NAME: str = "BTZ Kantine"

    # Debug mode (should be False in production) / Debug-Modus (in Produktion False setzen)
    DEBUG: bool = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")

    # JWT security configuration / JWT-Sicherheitskonfiguration
    SECRET_KEY: str = os.getenv("SECRET_KEY", "")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    REFRESH_SECRET: str = os.getenv("REFRESH_SECRET", "")
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

    # CORS origins (for frontend connection) / CORS-Ursprünge (für Frontend-Zugriff)
    BACKEND_CORS_ORIGINS: List[str] = os.getenv(
        "BACKEND_CORS_ORIGINS", "http://localhost:3000"
    ).split(",")

    # Database connection string / Datenbank-Verbindungszeichenfolge
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./canteen.db")

    # Initial superuser (used on first startup or demo) / Standard-Admin (für Setup oder Demo)
    FIRST_SUPERUSER: str = os.getenv("FIRST_SUPERUSER", "admin")
    FIRST_SUPERUSER_PASSWORD: str = os.getenv("FIRST_SUPERUSER_PASSWORD", "admin123")

    # Cookie settings for JWT tokens / Cookie-Einstellungen für JWT-Tokens
    COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "True").lower() in ("true", "1", "t")
    COOKIE_SAMESITE: str = os.getenv("COOKIE_SAMESITE", "lax")
    COOKIE_HTTPONLY: bool = os.getenv("COOKIE_HTTPONLY", "True").lower() in ("true", "1", "t")

    class Config:
        case_sensitive = True

# Create settings instance / Instanziere Einstellungen
settings = Settings()

# Warn if default admin credentials are still active / Warnung bei aktiven Standard-Zugangsdaten
if (
    settings.FIRST_SUPERUSER == "admin" and
    settings.FIRST_SUPERUSER_PASSWORD == "admin123"
):
    print("⚠ WARNING: Default admin credentials 'admin/admin123' are active!")
    print("Please change FIRST_SUPERUSER and FIRST_SUPERUSER_PASSWORD in your .env file.")
