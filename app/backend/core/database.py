"""CYBERGUARD Database Connection and Session Management."""
import logging
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.backend.core.config import settings

logger = logging.getLogger(__name__)

# Base declarative class for models
Base = declarative_base()

# Configure engine with pooling and pre-ping
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    echo=settings.DEBUG,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Dependency that yields a database session and ensures proper closure."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_connection() -> bool:
    """Check if the database is reachable."""
    try:
        with engine.connect() as conn:
            conn.execute(Base.metadata.schema and None or "SELECT 1")
        return True
    except Exception as exc:
        logger.warning("Database connection check failed: %s", exc)
        return False
