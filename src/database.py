"""
Database layer for the phishing detection system. Provides ORM models,
session management, raw connection fallbacks, and unified telemetry aggregation.
"""

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
    func,
    text,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

try:
    from src.config import DATABASE_URL, DB_PATH
except ImportError:
    DATABASE_URL = "sqlite:///phishing.db"
    DB_PATH = "phishing.db"

logger = logging.getLogger(__name__)


def _is_special_sqlite_target(target_path: str) -> bool:
    """Checks whether the database target is an in-memory DB or URI string."""
    if not target_path:
        return True
    path_str = target_path.strip().lower()
    return (
        path_str == ":memory:"
        or path_str.startswith("file:")
        or path_str.startswith("sqlite:")
        or "mode=memory" in path_str
        or ":memory:" in path_str
    )


def _ensure_parent_directory(target_path: str) -> None:
    """Safely creates parent directories for file paths, guarding against special SQLite URIs."""
    if _is_special_sqlite_target(target_path):
        return

    clean_path = target_path.replace("sqlite:///", "")
    if _is_special_sqlite_target(clean_path):
        return

    try:
        db_file = Path(clean_path).resolve()
        if db_file.parent and not db_file.parent.exists():
            db_file.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.warning(f"Could not create parent directory for '{target_path}': {e}")


# Fallback DB path resolution
if DATABASE_URL.startswith("sqlite"):
    RESOLVED_DB_PATH = DATABASE_URL.replace("sqlite:///", "")
else:
    RESOLVED_DB_PATH = str(DB_PATH)

DB_PATH = RESOLVED_DB_PATH


class Base(DeclarativeBase):
    pass


# Engine & Session Setup
connect_args = (
    {"check_same_thread": False, "timeout": 15}
    if DATABASE_URL.startswith("sqlite")
    else {}
)
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True, nullable=False)
    prediction = Column(String, nullable=False, default="unknown")
    is_phishing = Column(Boolean, nullable=False, default=False)
    risk_score = Column(Float, nullable=False, default=0.0)
    risk_level = Column(String, nullable=False, default="LOW")
    confidence = Column(Float, nullable=False, default=0.0)
    heuristics_json = Column(Text, nullable=True)
    features_json = Column(Text, nullable=True)
    scanned_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    @property
    def heuristics_triggered(self) -> List[Any]:
        if not self.heuristics_json:
            return []
        try:
            data = json.loads(self.heuristics_json)
            return data if isinstance(data, list) else []
        except (json.JSONDecodeError, TypeError, ValueError):
            return []

    @property
    def created_at(self) -> Optional[str]:
        return self.scanned_at.isoformat() if self.scanned_at else None


def safe_commit(session: Session) -> bool:
    """Safely commits a session and handles potential database errors."""
    try:
        session.commit()
        return True
    except SQLAlchemyError as e:
        if hasattr(session, "rollback"):
            session.rollback()
        logger.error(f"❌ Database error on commit: {e}")
        return False


def _get_session(
    provided_session: Optional[Any] = None,
) -> Tuple[Optional[Any], bool]:
    """Resolves an active session and returns (session, should_close)."""
    if provided_session is not None:
        # Check for Session instances or duck-typed MagicMock sessions
        if isinstance(provided_session, Session) or hasattr(provided_session, "query"):
            return provided_session, False

    if callable(SessionLocal):
        try:
            return SessionLocal(), True
        except (SQLAlchemyError, Exception) as e:
            logger.warning(f"SessionLocal invocation failed: {e}")

    try:
        fallback_session = sessionmaker(
            autocommit=False, autoflush=False, bind=engine
        )()
        return fallback_session, True
    except (SQLAlchemyError, Exception) as e:
        logger.error(f"Failed to resolve fallback database session: {e}")
        return None, False


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Returns a native sqlite3 connection configured with Row factory."""
    target_path = db_path or DB_PATH
    _ensure_parent_directory(target_path)

    conn = sqlite3.connect(target_path, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Initializes database tables on disk or in memory."""
    global engine, SessionLocal
    target_path = db_path or DB_PATH
    _ensure_parent_directory(target_path)

    try:
        if db_path or not engine:
            connection_url = (
                target_path
                if target_path.startswith("sqlite")
                else f"sqlite:///{target_path}"
            )
            engine = create_engine(
                connection_url,
                connect_args={"check_same_thread": False},
            )
            SessionLocal.configure(bind=engine)

        Base.metadata.create_all(bind=engine)
    except SQLAlchemyError as e:
        logger.error(f"Error initializing database schema via SQLAlchemy: {e}")
        raise


def get_db():
    """FastAPI Dependency yield generator ensuring strict transaction cleanup and exception propagation."""
    db, should_close = _get_session()
    if db is None:
        raise RuntimeError("Could not establish database session")
    try:
        yield db
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"SQLAlchemy error in database dependency: {e}")
        raise
    except Exception:
        db.rollback()
        raise
    finally:
        if should_close and db:
            db.close()


def check_db_health(
    session: Optional[Union[Session, sqlite3.Connection]] = None
) -> bool:
    """Checks database connectivity by executing a lightweight ping query targeting the resolved session or connection."""
    if session is not None:
        try:
            if isinstance(session, Session) or hasattr(session, "execute"):
                session.execute(text("SELECT 1"))
            elif hasattr(session, "cursor"):
                cursor = session.cursor()
                cursor.execute("SELECT 1")
            else:
                session.execute(text("SELECT 1"))
            return True
        except (SQLAlchemyError, Exception) as e:
            logger.error(f"Database health check failed via passed target: {e}")
            return False

    db, should_close = _get_session()
    if db is None:
        return False
    try:
        db.execute(text("SELECT 1"))
        return True
    except (SQLAlchemyError, Exception) as e:
        logger.error(f"Database health check failed: {e}")
        return False
    finally:
        if should_close and db:
            db.close()


def log_scan(
    result: dict, session: Optional[Any] = None
) -> Optional[Union[int, ScanLog]]:
    """Persists a URL inspection result record into the database."""
    # 1. Fallback to raw connection if passed a native sqlite3 connection or non-Session object
    if session is not None and not (isinstance(session, Session) or hasattr(session, "query")):
        try:
            cursor = session.cursor()
            heuristics = result.get("heuristics_triggered", [])
            heuristics_str = json.dumps(
                heuristics if isinstance(heuristics, list) else []
            )

            cursor.execute(
                """
                INSERT INTO scan_logs (url, prediction, risk_score, risk_level, confidence, heuristics_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    result.get("url", ""),
                    result.get("prediction", "legitimate"),
                    float(result.get("risk_score", 0.0)),
                    str(result.get("risk_level", "LOW")),
                    float(result.get("confidence", 0.0)),
                    heuristics_str,
                ),
            )
            if hasattr(session, "commit"):
                session.commit()
            return getattr(cursor, "lastrowid", None)
        except (SQLAlchemyError, Exception) as e:
            logger.error(f"❌ Raw SQLite log_scan error: {e}")
            try:
                if hasattr(session, "rollback"):
                    session.rollback()
            except Exception:
                pass
            return None

    # 2. Standard SQLAlchemy persistence path targeting the resolved session
    db, should_close = _get_session(session)
    if db is None:
        logger.error("❌ Database logging failed: No session available")
        return None

    try:
        url = result.get("url", "")
        prediction = result.get("prediction")
        if prediction is None:
            prediction = (
                "phishing" if result.get("is_phishing", False) else "legitimate"
            )

        is_phishing = bool(
            result.get("is_phishing", str(prediction).lower() == "phishing")
        )
        risk_score = float(
            result.get("risk_score", result.get("confidence_score", 0.0))
        )
        confidence = float(
            result.get("confidence", result.get("confidence_score", 0.0))
        )
        risk_level = str(result.get("risk_level", "LOW")).upper()

        heuristics_raw = result.get("heuristics_triggered", [])
        features_raw = result.get("features", {})

        heuristics_str = json.dumps(
            heuristics_raw if isinstance(heuristics_raw, list) else []
        )
        features_str = json.dumps(
            features_raw if isinstance(features_raw, dict) else {}
        )

        scan_entry = ScanLog(
            url=url,
            prediction=str(prediction),
            is_phishing=is_phishing,
            risk_score=risk_score,
            risk_level=risk_level,
            confidence=confidence,
            heuristics_json=heuristics_str,
            features_json=features_str,
        )

        db.add(scan_entry)
        db.commit()
        db.refresh(scan_entry)
        return scan_entry.id if result.get("return_id_only") else scan_entry
    except (SQLAlchemyError, Exception) as e:
        if hasattr(db, "rollback"):
            db.rollback()
        logger.error(f"❌ SQLAlchemy log_scan error: {e}")
        return None
    finally:
        if should_close and db:
            db.close()


def get_scan_history(
    limit: int = 50, session: Optional[Session] = None
) -> List[Dict[str, Any]]:
    """Retrieves recent scan logs ordered from newest to oldest as serialized dictionaries."""
    db, should_close = _get_session(session)
    if db is None:
        raise RuntimeError("No database session available for get_scan_history")

    try:
        logs = (
            db.query(ScanLog)
            .order_by(ScanLog.id.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": log.id,
                "url": log.url,
                "prediction": log.prediction,
                "is_phishing": log.is_phishing,
                "risk_score": log.risk_score,
                "confidence_score": log.confidence,
                "risk_level": log.risk_level,
                "confidence": log.confidence,
                "heuristics_triggered": log.heuristics_triggered,
                "scanned_at": (
                    log.scanned_at.isoformat() if log.scanned_at else None
                ),
                "created_at": log.created_at,
            }
            for log in logs
        ]
    except (SQLAlchemyError, Exception) as e:
        if hasattr(db, "rollback"):
            db.rollback()
        logger.error(f"SQLAlchemy error reading scan history: {e}")
        return []
    finally:
        if should_close and db:
            db.close()


def get_telemetry_stats(session: Optional[Session] = None) -> Dict[str, Any]:
    """Aggregates telemetry metrics across historical scans with unified schema key names."""
    db, should_close = _get_session(session)
    if db is None:
        raise RuntimeError("No database session available for get_telemetry_stats")

    empty_telemetry = {
        "total_scans": 0,
        "phishing_detected": 0,
        "clean_urls": 0,
        "average_risk_score": 0.0,
        "phishing_rate_percentage": 0.0,
        "phishing_percentage": 0.0,
        "top_heuristics": {},
        "total_phishing": 0,
        "legitimate_detected": 0,
        "legitimate_scans": 0,
        "total_legitimate": 0,
        "phishing_ratio": 0.0,
    }

    try:
        total_scans = db.query(ScanLog).count()
        if total_scans == 0:
            return empty_telemetry

        total_phishing = (
            db.query(ScanLog)
            .filter(
                (ScanLog.is_phishing == True)
                | (func.lower(ScanLog.prediction) == "phishing")
            )
            .count()
        )
        total_legitimate = total_scans - total_phishing
        phishing_rate = round((total_phishing / total_scans) * 100, 2)

        avg_score_res = db.query(func.avg(ScanLog.risk_score)).scalar()
        avg_score = (
            round(float(avg_score_res), 2) if avg_score_res is not None else 0.0
        )

        recent_heuristics = (
            db.query(ScanLog.heuristics_json)
            .filter(ScanLog.heuristics_json.isnot(None))
            .order_by(ScanLog.id.desc())
            .limit(1000)
            .all()
        )
        top_heuristics: Dict[str, int] = {}
        for (h_json,) in recent_heuristics:
            if h_json:
                try:
                    rules = json.loads(h_json)
                    for rule in rules:
                        rule_key = (
                            rule["rule"]
                            if isinstance(rule, dict)
                            else str(rule)
                        )
                        top_heuristics[rule_key] = (
                            top_heuristics.get(rule_key, 0) + 1
                        )
                except Exception:
                    continue

        return {
            "total_scans": total_scans,
            "phishing_detected": total_phishing,
            "clean_urls": total_legitimate,
            "average_risk_score": avg_score,
            "phishing_rate_percentage": phishing_rate,
            "phishing_percentage": phishing_rate,
            "top_heuristics": top_heuristics,
            "total_phishing": total_phishing,
            "legitimate_detected": total_legitimate,
            "legitimate_scans": total_legitimate,
            "total_legitimate": total_legitimate,
            "phishing_ratio": phishing_rate,
        }
    except (SQLAlchemyError, Exception) as e:
        if hasattr(db, "rollback"):
            db.rollback()
        logger.error(f"SQLAlchemy error loading telemetry stats: {e}")
        return empty_telemetry
    finally:
        if should_close and db:
            db.close()