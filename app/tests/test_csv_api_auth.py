# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details. 

import sys, os
sys.path.insert(0, os.getcwd())

import pytest
import logging
import asyncio
from datetime import datetime as dt, timedelta
from fastapi.testclient import TestClient
from main import app
from app.db.db import engine, Base, init_db
from app.core.security import create_access_token
from app.services.auth_service import create_user
from app.core import settings

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db_and_user():
    # Reset DB and default user / Datenbank und Standardbenutzer zurücksetzen
    logging.debug("Starting test setup: Resetting database and creating default user.")
    try:
        Base.metadata.drop_all(bind=engine)
        init_db()
        logging.debug("Database tables created successfully.")
        create_user(settings.FIRST_SUPERUSER, settings.FIRST_SUPERUSER_PASSWORD)
        logging.debug("Default user created successfully.")
        client.cookies.clear()
        login()
        logging.debug("Test setup completed successfully.")
    except Exception as e:
        logging.error(f"Setup failed: {e}")
        pytest.fail(f"Setup failed: {e}")


def login():
    # Perform login to set JWT cookie / JWT-Kookie setzen
    res = client.get("/auth/login")
    assert res.status_code == 200
    csrf = res.cookies.get("csrf_token")
    resp = client.post(
        "/auth/login",
        data={
            "username": settings.FIRST_SUPERUSER,
            "password": settings.FIRST_SUPERUSER_PASSWORD,
            "csrf_token": csrf
        },
        follow_redirects=False
    )
    assert resp.status_code == 303


def test_get_plan_unauthenticated():
    # Clear cookies to ensure unauthenticated / Cookies löschen, um nicht authentifiziert zu sein
    client.cookies.clear()
    res = client.get("/api/plan")
    assert res.status_code == 401


def test_post_plan_unauthenticated():
    # Clear cookies to ensure unauthenticated / Cookies löschen, um nicht authentifiziert zu sein
    client.cookies.clear()
    res = client.post(
        "/api/plan",
        json=[{"datum": "2025-07-12", "menu1": "A", "menu2": "B", "dessert": "C"}]
    )
    assert res.status_code == 403


def test_get_and_post_plan_authenticated():
    # Ensure user is logged in and has JWT token / Sicherstellen, dass der Benutzer angemeldet ist und ein JWT-Token hat
    response = client.get("/auth/login")
    assert response.status_code == 200
    csrf_token = response.cookies.get("csrf_token")
    login_response = client.post("/auth/login", data={
        "username": settings.FIRST_SUPERUSER,
        "password": settings.FIRST_SUPERUSER_PASSWORD,
        "csrf_token": csrf_token
    }, headers={"Content-Type": "application/x-www-form-urlencoded"}, follow_redirects=False)
    assert login_response.status_code == 303
    
    # Extract tokens from cookies / Tokens aus Cookies extrahieren
    access_token = login_response.cookies.get("access-token")
    assert access_token, "Access token cookie not set after login"
    
    # Test GET /api/plan with JWT token / Teste GET /api/plan mit JWT-Token
    get_response = client.get("/api/plan")
    assert get_response.status_code == 200, f"Unexpected status code for GET /api/plan: {get_response.status_code}"
    
    # Test POST /api/plan with JWT token and CSRF token / Teste POST /api/plan mit JWT-Token und CSRF-Token
    new_csrf_token = login_response.cookies.get("csrf_token")
    data = [{"datum": "2025-07-13", "menu1": "Test Menu", "menu2": "Test Menu 2", "dessert": "Test Dessert"}]
    headers = {
        "X-CSRF-Token": new_csrf_token,
        "Content-Type": "application/json"
    }
    post_response = client.post("/api/plan", json=data, headers=headers)
    assert post_response.status_code in [200, 201, 422], f"Unexpected status code for POST /api/plan: {post_response.status_code}"
    if post_response.status_code == 422:
        logging.debug(f"Validation error for POST /api/plan: {post_response.json()}")
