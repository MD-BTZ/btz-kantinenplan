# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

from pydantic_settings import BaseSettings
from typing import List, Optional, Any, Dict, Union
from pathlib import Path
import os
from dotenv import load_dotenv

# Load environment variables from .env file / Umgebungsvariablen aus .env-Datei laden
load_dotenv()

class Settings(BaseSettings):
    # Project settings / Projekteinstellungen
    PROJECT_NAME: str = "BTZ Kantine"
    DEBUG: bool = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")
    
    # Security / Sicherheit
    SECRET_KEY: str = os.getenv("SECRET_KEY", "")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    
    # Cross-Origin Resource Sharing
    BACKEND_CORS_ORIGINS: List[str] = os.getenv(
        "BACKEND_CORS_ORIGINS", "*"
    ).split(",")
    
    # Database / Datenbank
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./canteen.db")
    
    # Admin
    FIRST_SUPERUSER: str = os.getenv("FIRST_SUPERUSER", "admin")
    FIRST_SUPERUSER_PASSWORD: str = os.getenv("FIRST_SUPERUSER_PASSWORD", "admin123")
    
    class Config:
        case_sensitive = True

# Create settings instance / Einstellungen-Instanz erstellen
settings = Settings()