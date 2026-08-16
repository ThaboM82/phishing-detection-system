import os
import logging
from typing import Generator
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session

logger = logging.getLogger("phishing_system.database")

# --- DATABASE CONNECTION CONFIGURATION ---
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./phishing_threats.db")
is_sqlite = DATABASE_URL.startswith("sqlite")

connect_args = {"check_same_thread": False} if is_sqlite else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
    echo=False,
)

# Enable Foreign Key enforcement for SQLite
if is_sqlite:
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


# --- SESSION & BASE SETUP ---
Base = declarative_base()

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)


# --- DATABASE DEPENDENCIES & INITIALIZATION ---

def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency yielding a transactional database session context.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception as exc:
        db.rollback()
        logger.error(f"Database session error: {exc}")
        raise
    finally:
        db.close()


def init_db() -> None:
    """
    Creates database tables defined in metadata.
    """
    import src.models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized successfully.")


def check_db_health() -> bool:
    """
    Verifies active database connectivity.
    """
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False