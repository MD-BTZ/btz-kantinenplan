# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.responses import StreamingResponse
import secrets
import logging

def get_csrf_token(request: Request):
    cookie_token = request.cookies.get("csrf_token")
    header_token = request.headers.get("X-CSRF-Token")
    
    logging.debug(f"CSRF Middleware: Cookie token: {cookie_token}, Header token: {header_token}")

    if not cookie_token or not header_token:
        logging.error(f"CSRF Middleware: Missing CSRF token. Cookie token: {cookie_token}, Header token: {header_token}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing"
        )
    
    if cookie_token != header_token:
        logging.error(f"CSRF Middleware: CSRF token mismatch. Cookie token: {cookie_token}, Header token: {header_token}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token mismatch"
        )
    
    logging.debug(f"CSRF Middleware: Valid CSRF token. Token: {cookie_token}")
    return cookie_token

# Dependency for CSRF protection / Abhängigkeit für CSRF-Schutz
def csrf_protected(request: Request):
    return get_csrf_token(request)

class CSRFMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, secret_key: str = None):
        super().__init__(app)
        self.secret_key = secret_key

    async def dispatch(self, request: Request, call_next):
        # Safe methods: generate CSRF token cookie if missing / Sicherheitsmethoden: CSRF-Token-Kookie generieren, wenn fehlend
        if request.method in ("GET", "HEAD", "OPTIONS"):
            response = await call_next(request)
            logging.debug("CSRF Middleware: Safe method, setting CSRF token.")
            token = request.cookies.get("csrf_token") or secrets.token_urlsafe(32)
            logging.debug(f"CSRF Middleware: Token before setting cookie: {token}")
            # Ensure response supports cookies before setting
            if hasattr(response, 'set_cookie'):
                response.set_cookie(key="csrf_token", value=token, httponly=True)
                logging.debug(f"CSRF Middleware: Cookie set successfully. Token: {token}")
            else:
                logging.debug("CSRF Middleware: Response does not support cookies.")
            return response

        # Skip CSRF for login POST; handler does its own validation / Überspringe CSRF für Login POST; Handler überprüft selbst
        if request.method == "POST" and request.url.path == "/auth/login":
            logging.debug("CSRF Middleware: Skipping CSRF validation for login POST.")
            return await call_next(request)

        # State-changing methods: enforce CSRF for all content types / Zustandsändernde Methoden: CSRF für alle Content-Typen erzwingen
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            logging.debug("CSRF Middleware: State-changing method, validating CSRF token.")
            try:
                csrf_protected(request)
            except HTTPException as e:
                logging.error(f"CSRF Middleware: Validation failed with error {e.detail}")
                return JSONResponse({"detail": e.detail}, status_code=e.status_code)
        return await call_next(request)
