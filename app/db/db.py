# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from app.core import settings

# Create SQLAlchemy engine / SQLAlchemy Engine erstellen
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)

# Session factory / Session-Fabrik
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models / Basisklasse für Modelle
Base = declarative_base()

def init_db():
    # Initialize database and create tables / Datenbank initialisieren und Tabellen erstellen
    # Import models to ensure they are registered with Base / Importiert Modelle, um sicherzustellen, dass sie bei Base registriert sind
    from . import models  # noqa: F401
    
    # Create all tables / Alle Tabellen erstellen
    Base.metadata.create_all(bind=engine)
    print("Database tables created")
