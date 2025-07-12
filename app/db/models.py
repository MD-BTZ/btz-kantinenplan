# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

from sqlalchemy import Column, Integer, String, DateTime, Boolean
import datetime
from .db import Base

class User(Base):
    # User model for authentication / Benutzermodell für Authentifizierung
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)  # Admin-Permissions / Admin-Berechtigung
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}')>"
