# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details. 

import sys, os
sys.path.insert(0, os.getcwd())

import pytest
from fastapi.testclient import TestClient
from main import app
from app.db.db import engine, Base, init_db
from app.services.auth_service import create_user
from app.core import settings

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db_and_user():
    # Reset DB and default user / Datenbank und Standardbenutzer zurücksetzen
    Base.metadata.drop_all(bind=engine)
    init_db()
    create_user(settings.FIRST_SUPERUSER, settings.FIRST_SUPERUSER_PASSWORD)
    client.cookies.clear()
    # Log in to set JWT cookie for JSON API tests / JWT-Kookie für JSON-API-Tests setzen
    login()


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
    assert res.status_code == 401


def test_get_and_post_plan_authenticated():
    # Initial GET should return list / Initial GET sollte Liste zurückgeben
    res = client.get("/api/plan")
    assert res.status_code == 200
    assert isinstance(res.json(), list)

    # POST new plan data / POST neues Plan-Daten
    data = [{"datum": "2025-07-13", "menu1": "X", "menu2": "Y", "dessert": "Z"}]
    res2 = client.post("/api/plan", json=data)
    assert res2.status_code == 200
    assert res2.json() == {"status": "success"}

    # Verify GET reflects posted data / GET sollte die posted Daten widerspiegeln
    res3 = client.get("/api/plan")
    assert res3.status_code == 200
    assert res3.json() == data
