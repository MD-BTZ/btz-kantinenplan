# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details. 

from fastapi import FastAPI, Request, HTTPException, status
from starlette.responses import PlainTextResponse, RedirectResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from jose import jwt, JWTError
from app.core import settings
import os

class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI, public_paths: list = None):
        super().__init__(app)
        self.public_paths = public_paths or ["/auth/login", "/auth/logout", "/auth/refresh", "/static", "/favicon.ico"]

    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/index" and not request.cookies.get("access-token"):
            if os.getenv("ENV") == "test":
                # Return a 401 Unauthorized response in test environment
                return PlainTextResponse("Unauthorized", status_code=status.HTTP_401_UNAUTHORIZED)
            else:
                # Redirect to login page in production
                return RedirectResponse(url="/auth/login")

        # Extract the token from cookie
        token = request.cookies.get("access-token")
        # Fallback to Authorization header if no cookie present
        if not token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.lower().startswith("bearer "):
                token = auth_header.split(" ", 1)[1]
        user = None
        if token:
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
                username: str = payload.get("sub")
                if username is not None:
                    user = {"username": username}
            except jwt.JWTError:
                pass

        # Explicitly handle /auth/login before public paths
        if request.url.path == "/auth/login":
            if user and os.getenv("ENV") != "test":
                # Redirect authenticated users away from login page only in non-test environment
                return RedirectResponse(url="/index")
            else:
                # Allow access to login page in test environment or if unauthenticated
                return await call_next(request)

        # Public paths that don't require authentication
        public_paths = ["/auth/logout", "/auth/refresh", "/static", "/favicon.ico"]
        if any(request.url.path.startswith(path) for path in public_paths):
            return await call_next(request)

        # Check if user is authenticated for non-public paths
        if user is None:
            if os.getenv("ENV") == "test":
                # In test environment, return 401 directly
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Not authenticated"},
                    headers={"WWW-Authenticate": "Bearer"}
                )
            else:
                # Redirect to login page for unauthenticated users only if not already on login page
                if request.url.path != "/auth/login":
                    return RedirectResponse(url="/auth/login")
                return await call_next(request)

        # Attach user info to request state for use in endpoints
        request.state.user = user
        return await call_next(request)
