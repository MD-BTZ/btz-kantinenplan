# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

import sys, os
sys.path.insert(0, os.getcwd())

import re
import pytest
import datetime
from datetime import timedelta
from fastapi.testclient import TestClient
from main import app
from app.services.auth_service import create_user
from app.core import settings
from app.core.security import manager, create_access_token
from app.db.db import engine, Base, init_db
import logging
import asyncio

# Configure logging for the test setup / Konfiguriere Logging für die Test-Setup
logging.basicConfig(level=logging.DEBUG)

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db_and_user():
    logging.debug("Starting test setup: Resetting database and creating default user.")
    try:
        Base.metadata.drop_all(bind=engine)
        init_db()
        logging.debug("Database tables created successfully.")
        create_user(settings.FIRST_SUPERUSER, settings.FIRST_SUPERUSER_PASSWORD)
        logging.debug("Default user created successfully.")
        # Use asyncio.run to handle the async token creation / Verwende asyncio.run, um die asynchrone Token-Erstellung zu verwalten
        access_token = asyncio.run(create_access_token({"sub": settings.FIRST_SUPERUSER}, expires_delta=timedelta(minutes=30)))
        logging.debug(f"Access token created: {access_token}")
        client.cookies.set("access-token", access_token)
        logging.debug("Access token set in client cookies.")
        logging.debug("Test setup completed successfully.")
    except Exception as e:
        logging.error(f"Setup failed: {e}")
        pytest.fail(f"Setup failed: {e}")


def test_csrf_token_present():
    response = client.get("/auth/login")
    assert response.status_code == 200
    assert "csrf_token" in response.cookies
    html = response.text
    assert 'name="csrf_token"' in html
    # Removed check for value attribute since it's set dynamically via JavaScript
    print("CSRF token input field present in login form")


def test_login_invalid_credentials():
    # get csrf token / CSRF-Token abrufen
    response = client.get("/auth/login")
    csrf = response.cookies.get("csrf_token")
    res = client.post("/auth/login", data={
        "username": settings.FIRST_SUPERUSER,
        "password": "wrongpassword",
        "csrf_token": csrf
    }, headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert res.status_code == 401
    assert "detail" in res.json()
    assert res.json()["detail"] == "Incorrect username or password"


def test_login_valid_credentials():
    response = client.get("/auth/login")
    csrf = response.cookies.get("csrf_token")
    res = client.post(
        "/auth/login", data={
            "username": settings.FIRST_SUPERUSER,
            "password": settings.FIRST_SUPERUSER_PASSWORD,
            "csrf_token": csrf
        }, headers={"Content-Type": "application/x-www-form-urlencoded"}, follow_redirects=False
    )
    # Should redirect / Sollte umleiten
    assert res.status_code == 303
    # Should set JWT cookie / JWT-Kookie setzen
    assert "access-token" in res.cookies


def test_login_missing_csrf_token():
    # Attempt login without CSRF token / Versuch, sich ohne CSRF-Token anzumelden
    response = client.get("/auth/login")
    assert response.status_code == 200
    res = client.post("/auth/login", data={
        "username": settings.FIRST_SUPERUSER,
        "password": settings.FIRST_SUPERUSER_PASSWORD
    }, headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert res.status_code == 403
    assert "detail" in res.json()
    assert res.json()["detail"] == "CSRF token mismatch"


def test_login_invalid_csrf_token():
    # Attempt login with invalid CSRF token / Versuch, sich mit ungültigem CSRF-Token anzumelden
    response = client.get("/auth/login")
    assert response.status_code == 200
    res = client.post("/auth/login", data={
        "username": settings.FIRST_SUPERUSER,
        "password": settings.FIRST_SUPERUSER_PASSWORD,
        "csrf_token": "invalid"
    }, headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert res.status_code == 403
    assert "detail" in res.json()
    assert res.json()["detail"] == "CSRF token mismatch"
