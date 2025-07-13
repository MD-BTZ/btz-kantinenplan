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
    # Clear cookies to avoid redirection
    client.cookies.clear()
    response = client.get("/auth/login", follow_redirects=False)
    csrf_token = response.cookies.get("csrf_token")
    logging.debug("Response cookies: %s", response.cookies)
    assert response.status_code == 200
    assert csrf_token is not None
    html = response.text
    logging.debug("HTML content: %s", html)
    assert "name=\"csrf_token\"" in html
    # Check for the presence of a value attribute with a token-like string
    assert "value=\"" in html
    logging.debug("CSRF token input field present in login form")


def test_login_invalid_credentials():
    response = client.get("/auth/login", follow_redirects=False)
    csrf = response.cookies.get("csrf_token")
    logging.debug("CSRF token for invalid credentials test: %s", csrf)
    res = client.post("/auth/login", data={
        "username": settings.FIRST_SUPERUSER,
        "password": "wrongpassword",
        "csrf_token": csrf
    }, headers={"Content-Type": "application/x-www-form-urlencoded"}, follow_redirects=False)
    logging.debug("Response status for invalid credentials: %s", res.status_code)
    assert res.status_code == 401
    assert "detail" in res.json()
    assert res.json()["detail"] == "Incorrect username or password"


def test_login_valid_credentials():
    response = client.get("/auth/login", follow_redirects=False)
    csrf = response.cookies.get("csrf_token")
    logging.debug("CSRF token for valid credentials test: %s", csrf)
    res = client.post(
        "/auth/login", data={
            "username": settings.FIRST_SUPERUSER,
            "password": settings.FIRST_SUPERUSER_PASSWORD,
            "csrf_token": csrf
        }, headers={"Content-Type": "application/x-www-form-urlencoded"}, follow_redirects=False
    )
    logging.debug("Response status for valid credentials: %s", res.status_code)
    assert res.status_code == 303
    # Should set JWT cookie
    logging.debug("Response cookies after valid login: %s", res.cookies)
    assert "access-token" in res.cookies
    assert "refresh-token" in res.cookies
    assert "csrf_token" in res.cookies


def test_api_with_correct_csrf_header():
    response = client.get("/auth/login", follow_redirects=False)
    csrf = response.cookies.get("csrf_token")
    logging.debug("CSRF token for API test: %s", csrf)
    # Ensure we login first
    login_res = client.post(
        "/auth/login", data={
            "username": settings.FIRST_SUPERUSER,
            "password": settings.FIRST_SUPERUSER_PASSWORD,
            "csrf_token": csrf
        }, headers={"Content-Type": "application/x-www-form-urlencoded"}, follow_redirects=False
    )
    assert login_res.status_code == 303
    # Get the new CSRF token after login
    new_csrf = login_res.cookies.get("csrf_token")
    res = client.get("/api/plan", headers={"X-CSRF-Token": new_csrf}, follow_redirects=False)
    assert res.status_code == 200


def test_login_missing_csrf_token():
    response = client.get("/auth/login", follow_redirects=False)
    logging.debug("Response cookies: %s", response.cookies)
    res = client.post("/auth/login", data={
        "username": settings.FIRST_SUPERUSER,
        "password": settings.FIRST_SUPERUSER_PASSWORD
    }, headers={"Content-Type": "application/x-www-form-urlencoded"}, follow_redirects=False)
    logging.debug("Response status for missing CSRF token: %s", res.status_code)
    assert res.status_code == 403
    assert "detail" in res.json()
    assert res.json()["detail"] == "CSRF token mismatch"


def test_login_invalid_csrf_token():
    response = client.get("/auth/login", follow_redirects=False)
    logging.debug("Response cookies: %s", response.cookies)
    res = client.post("/auth/login", data={
        "username": settings.FIRST_SUPERUSER,
        "password": settings.FIRST_SUPERUSER_PASSWORD,
        "csrf_token": "invalid_token"
    }, headers={"Content-Type": "application/x-www-form-urlencoded"}, follow_redirects=False)
    logging.debug("Response status for invalid CSRF token: %s", res.status_code)
    assert res.status_code == 403
    assert "detail" in res.json()
    assert res.json()["detail"] == "CSRF token mismatch"


def test_index_access_with_token():
    # Clear cookies to prevent conflicts / Cookies löschen, um Konflikte zu vermeiden
    client.cookies.clear()

    # Perform GET request to set CSRF token / GET-Anfrage senden, um CSRF-Token zu setzen
    client.get("/auth/login", follow_redirects=False)
    csrf_token = client.cookies.get("csrf_token")

    # Perform login to obtain token / Login durchführen, um Token zu erhalten
    response = client.post("/auth/login", data={
        "username": settings.FIRST_SUPERUSER,
        "password": settings.FIRST_SUPERUSER_PASSWORD,
        "csrf_token": csrf_token
    }, headers={"Content-Type": "application/x-www-form-urlencoded"}, follow_redirects=False)
    assert response.status_code == 303

    # Set JWT token in headers for /index access / JWT-Token in Header für /index Zugriff setzen
    access_token = response.cookies.get("access-token")
    headers = {"Authorization": f"Bearer {access_token}"}

    # Access /index with valid token / Zugriff auf /index mit gültigem Token
    index_response = client.get("/index", headers=headers, follow_redirects=False)
    assert index_response.status_code == 200
    assert "Kantinenplan" in index_response.text 
    index_response = client.get("/index", headers=headers, follow_redirects=False)
    assert index_response.status_code == 200
    assert "Kantinenplan" in index_response.text 


def test_index_access_without_token():
    # Clear cookies to simulate no token / Cookies löschen, um keine Token zu simulieren
    client.cookies.clear()

    # Attempt to access /index without token / Versuch, sich ohne Token anzumelden
    index_response = client.get("/index", follow_redirects=False)
    assert index_response.status_code == 401


def test_static_index_access():
    # Attempt to access /static/index.html / Versuch, sich ohne Token anzumelden    
    static_response = client.get("/static/index.html", follow_redirects=False)
    assert static_response.status_code == 404


def test_csrf_token_in_form_and_cookie():
    # Clear cookies to avoid redirection
    client.cookies.clear()
    response = client.get("/auth/login", follow_redirects=False)
    assert response.status_code == 200
    assert "csrf_token" in response.text
    assert "csrf_token" in response.cookies


def test_login_without_csrf_token():
    response = client.post("/auth/login", data={
        "username": settings.FIRST_SUPERUSER,
        "password": settings.FIRST_SUPERUSER_PASSWORD
    }, follow_redirects=False)
    assert response.status_code == 403


def test_invalid_login_credentials():
    # Obtain a valid CSRF token
    csrf_token = client.get("/auth/login").cookies.get("csrf_token")
    # Attempt login with invalid credentials but valid CSRF token
    response = client.post("/auth/login", data={
        "username": "wrong_user",
        "password": "wrong_pass",
        "csrf_token": csrf_token  # Use valid CSRF token
    }, follow_redirects=False)
    assert response.status_code == 401  # Expect 401 for invalid credentials


def test_successful_login_sets_cookies():
    csrf_token = client.get("/auth/login").cookies.get("csrf_token")
    response = client.post("/auth/login", data={
        "username": settings.FIRST_SUPERUSER,
        "password": settings.FIRST_SUPERUSER_PASSWORD,
        "csrf_token": csrf_token
    }, follow_redirects=False)
    assert response.status_code == 303
    assert "access-token" in response.cookies
    assert "refresh-token" in response.cookies


def test_access_protected_route_with_token():
    csrf_token = client.get("/auth/login").cookies.get("csrf_token")
    client.post("/auth/login", data={
        "username": settings.FIRST_SUPERUSER,
        "password": settings.FIRST_SUPERUSER_PASSWORD,
        "csrf_token": csrf_token
    }, follow_redirects=False)
    response = client.get("/index", follow_redirects=False)
    assert response.status_code == 200


def test_redirect_logged_in_user_from_login():
    # Log in to set authentication cookies
    csrf_token = client.get("/auth/login").cookies.get("csrf_token")
    client.post("/auth/login", data={
        "username": settings.FIRST_SUPERUSER,
        "password": settings.FIRST_SUPERUSER_PASSWORD,
        "csrf_token": csrf_token
    }, follow_redirects=False)
    # Attempt to access login page again
    response = client.get("/auth/login", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["Location"] == "/index"  # Ensure redirection to index


def test_token_refresh_flow():
    # Clear cookies to ensure no access token is present
    client.cookies.clear()
    # Log in to set authentication and CSRF cookies
    csrf_token = client.get("/auth/login").cookies.get("csrf_token")
    login_response = client.post("/auth/login", data={
        "username": settings.FIRST_SUPERUSER,
        "password": settings.FIRST_SUPERUSER_PASSWORD,
        "csrf_token": csrf_token
    }, follow_redirects=False)
    # Retrieve the new CSRF token and refresh token after login
    new_csrf_token = login_response.cookies.get("csrf_token")
    refresh_token = login_response.cookies.get("refresh-token")
    # Set only the refresh-token and CSRF token on the client instance
    client.cookies.clear()
    client.cookies.set("csrf_token", new_csrf_token)
    client.cookies.set("refresh-token", refresh_token)
    # Use refresh token to obtain new access token
    response = client.post("/auth/refresh", headers={"X-CSRF-Token": new_csrf_token}, cookies={"refresh-token": refresh_token})
    assert response.status_code == 200
    assert "access-token" in response.cookies  # Ensure new access token is set
