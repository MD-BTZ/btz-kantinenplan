# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from fastapi.responses import JSONResponse
import secrets

class CSRFMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, cookie_name: str = "csrf_token", header_name: str = "X-CSRF-Token", form_field: str = "csrf_token", secret_key: str = None):
        super().__init__(app)
        self.cookie_name = cookie_name
        self.header_name = header_name
        self.form_field = form_field
        self.secret_key = secret_key

    async def dispatch(self, request: Request, call_next):
        # Safe methods: generate CSRF token cookie if missing / Sicherheitsmethoden: CSRF-Token-Kookie generieren, wenn fehlend
        if request.method in ("GET", "HEAD", "OPTIONS"):
            response = await call_next(request)
            # Skip overriding cookie for login_form to preserve template token / Überspringe Cookie-Überschreibung für login_form, um Template-Token beizubehalten
            if request.url.path == "/auth/login":
                return response
            token = request.cookies.get(self.cookie_name) or secrets.token_urlsafe(32)
            response.set_cookie(key=self.cookie_name, value=token, httponly=True)
            return response

        # Skip CSRF for login POST; handler does its own validation / Überspringe CSRF für Login POST; Handler überprüft selbst
        if request.method == "POST" and request.url.path == "/auth/login":
            return await call_next(request)

        # State-changing methods: enforce CSRF for form submissions only / Methoden, die den Zustand ändern: CSRF für Formulareinsendungen erzwingen
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            content_type = request.headers.get("content-type", "")
            # Only enforce CSRF for form data / Nur CSRF für Formulardaten erzwingen
            if content_type.startswith("application/x-www-form-urlencoded") or content_type.startswith("multipart/form-data"):
                token_cookie = request.cookies.get(self.cookie_name)
                form = await request.form()
                token_form = form.get(self.form_field)
                if not token_cookie or token_form != token_cookie:
                    return JSONResponse({"detail": "Invalid or missing CSRF token"}, status_code=403)
            # Skip CSRF check for other content types / CSRF-Prüfung für andere Content-Typen
        return await call_next(request)
