# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from csv_api import router as csv_router

# Optionally import additional routers (views, auth)
# Optional: Zusätzliche Router importieren (views, auth)
try:
    from views import router as views_router
except ImportError:
    views_router = None
try:
    from auth import router as auth_router
except ImportError:
    auth_router = None

# Create FastAPI app instance / FastAPI-App-Instanz erstellen
app = FastAPI()

# Mount static files directory / Verzeichnis für statische Dateien einbinden
app.mount("/static", StaticFiles(directory="static"), name="static")

# Set up Jinja2 templates directory / Jinja2-Templates-Verzeichnis setzen
templates = Jinja2Templates(directory="templates")

# Include routers / Router einbinden
if views_router:
    app.include_router(views_router)
if auth_router:
    app.include_router(auth_router)
app.include_router(csv_router)

# Start the app with: uvicorn main:app --reload
