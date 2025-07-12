# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.responses import StreamingResponse
import secrets
import logging

async def get_csrf_token(request: Request):
    cookie_token = request.cookies.get("csrf_token")
    header_token = request.headers.get("X-CSRF-Token")
    form_token = None
    
    # Log raw request body for debugging
    raw_body = await request.body()
    logging.debug(f"CSRF Middleware: Raw request body: {raw_body}")
    
    # Check for token in form data if it's a POST request with form content type
    content_type = request.headers.get("Content-Type", "").lower()
    if request.method == "POST" and ("application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type):
        try:
            form_data = await request.form()
            form_token = form_data.get("csrf_token")
            logging.debug(f"CSRF Middleware: Form token extracted: {form_token}")
        except Exception as e:
            logging.error(f"CSRF Middleware: Error extracting form data: {e}")
    
    logging.debug(f"CSRF Middleware: Cookie token: {cookie_token}, Header token: {header_token}, Form token: {form_token}")

    if not cookie_token:
        logging.error(f"CSRF Middleware: Missing CSRF token in cookie")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token mismatch"
        )
    
    # For HTML form submissions, token should be in form data; for API requests, in header
    token_to_compare = form_token if form_token is not None else header_token
    
    if token_to_compare is None:
        logging.error(f"CSRF Middleware: Missing CSRF token. Cookie token: {cookie_token}, Header token: {header_token}, Form token: {form_token}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token mismatch"
        )
    
    if cookie_token != token_to_compare:
        logging.error(f"CSRF Middleware: CSRF token mismatch. Cookie token: {cookie_token}, Compared token: {token_to_compare}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token mismatch"
        )
    
    logging.debug(f"CSRF Middleware: Valid CSRF token. Token: {cookie_token}")
    return cookie_token

# Dependency for CSRF protection / Abhängigkeit für CSRF-Schutz
async def csrf_protected(request: Request):
    return await get_csrf_token(request)

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
                response.set_cookie(key="csrf_token", value=token, httponly=False)
                logging.debug(f"CSRF Middleware: Cookie set successfully. Token: {token}")
            else:
                logging.debug("CSRF Middleware: Response does not support cookies.")
            return response

        # State-changing methods: enforce CSRF for all content types / Zustandsändernde Methoden: CSRF für alle Content-Typen erzwingen
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            logging.debug("CSRF Middleware: State-changing method, validating CSRF token.")
            try:
                await get_csrf_token(request)
            except HTTPException as e:
                logging.error(f"CSRF Middleware: Validation failed with error {e.detail}")
                return JSONResponse({"detail": e.detail}, status_code=e.status_code)
        return await call_next(request)
