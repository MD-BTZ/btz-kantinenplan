# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

from fastapi_login import LoginManager
from .settings import Settings
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

def get_current_user():
    # Dependency to get current user / Dependency um aktuellen Benutzer abzurufen
    return manager.current_user