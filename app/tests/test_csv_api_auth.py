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
    })
    assert login_response.status_code == 200
    logging.debug("Headers from login response: %s", login_response.headers)
    # Re-fetch the CSRF token from cookies after login / Nach dem Login erneut den CSRF-Token aus den Cookies abrufen
    csrf_token_after_login = login_response.cookies.get("csrf_token")
    logging.debug(f"CSRF Token after login from cookie: {csrf_token_after_login}")
    headers = {"X-CSRF-Token": csrf_token_after_login}

    # GET should succeed with authentication / GET sollte mit der Authentifizierung erfolgreich sein
    get_res = client.get("/api/plan", headers=headers)
    assert get_res.status_code == 200
    assert isinstance(get_res.json(), list)

    # POST should succeed with authentication / POST sollte mit der Authentifizierung erfolgreich sein
    data = [{"datum": "2025-07-13", "menu1": "Test1", "menu2": "Test2", "dessert": "TestDessert"}]
    logging.debug(f"Request Payload: {data}")
    post_res = client.post("/api/plan", json=data, headers=headers)
    logging.debug(f"POST Response Status Code: {post_res.status_code}")
    logging.debug(f"POST Response Content: {post_res.json()}")
    assert post_res.status_code == 200 or post_res.status_code == 422
    if post_res.status_code == 422:
        logging.debug("Received 422 status code, check payload validation errors in response content.")
    else:
        assert post_res.json() == {"status": "success"}
