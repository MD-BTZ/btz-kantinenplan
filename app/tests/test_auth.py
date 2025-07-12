# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

import sys, os
sys.path.insert(0, os.getcwd())

import re
import pytest
from fastapi.testclient import TestClient
from main import app
from app.services.auth_service import create_user
from app.core import settings
from app.core.security import manager
from app.db.db import engine, Base, init_db

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db_and_user():
    # Reset database / Datenbank zurücksetzen
    Base.metadata.drop_all(bind=engine)
    init_db()
    # Create default user / Standardbenutzer erstellen
    create_user(settings.FIRST_SUPERUSER, settings.FIRST_SUPERUSER_PASSWORD)


def test_csrf_token_present():
    response = client.get("/auth/login")
    assert response.status_code == 200
    assert "csrf_token" in response.cookies
    html = response.text
    assert 'name="csrf_token"' in html
    match = re.search(r'name="csrf_token" value="([^\"]+)"', html)
    assert match


def test_login_invalid_credentials():
    # get csrf token / CSRF-Token abrufen
    response = client.get("/auth/login")
    csrf = response.cookies.get("csrf_token")
    res = client.post("/auth/login", data={
        "username": "wrong",
        "password": "wrong",
        "csrf_token": csrf
    })
    assert res.status_code == 401
    assert "Invalid credentials" in res.text


def test_login_valid_credentials():
    response = client.get("/auth/login")
    csrf = response.cookies.get("csrf_token")
    res = client.post(
        "/auth/login", data={
            "username": settings.FIRST_SUPERUSER,
            "password": settings.FIRST_SUPERUSER_PASSWORD,
            "csrf_token": csrf
        }, follow_redirects=False
    )
    # Should redirect / Sollte umleiten
    assert res.status_code == 303
    # Should set JWT cookie / JWT-Kookie setzen
    assert manager.cookie_name in res.cookies
