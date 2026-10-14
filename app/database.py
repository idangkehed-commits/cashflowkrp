from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from .config import settings

# SQLite needs connect_args check_same_thread=False; PostgreSQL does not
connect_args = {}
if "sqlite" in settings.DATABASE_URL:
    connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True  # Automatically reconnect dropped DB connections (crucial for cloud DBs)
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """Dependency injection to provide clean database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
