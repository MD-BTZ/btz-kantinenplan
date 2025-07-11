from sqlalchemy import Column, Integer, String, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

# SQLite DB (can be changed later) / SQLite DB (kann später angepasst werden)
DATABASE_URL = 'sqlite:///canteen.db'

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

def init_db():
    Base.metadata.create_all(bind=engine)  # Create all tables / Alle Tabellen anlegen
