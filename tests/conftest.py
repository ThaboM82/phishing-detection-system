import asyncio
import os
import socket
import sys
import warnings
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.pool import StaticPool

# Import application database base/models and get_db dependency
import src.database as db

# =====================================================================
# CPython AST & Path Fixes
# =====================================================================

sys.setrecursionlimit(5000)
pytest.register_assert_rewrite("sklearn", "numpy", "scipy")
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from src.pipeline import PhishingDetectionPipeline
except ImportError:
    try:
        from src.pipeline import PhishingDetectorPipeline as PhishingDetectionPipeline
    except ImportError:
        from src.pipeline import PhishingPipeline as PhishingDetectionPipeline

PhishingPipeline = PhishingDetectionPipeline
PhishingDetectorPipeline = PhishingDetectionPipeline


def pytest_configure(config):
    """Globally suppress unraisable event loop teardown warnings and resource leaks."""
    warnings.filterwarnings("ignore", category=pytest.PytestUnraisableExceptionWarning)
    warnings.filterwarnings("ignore", category=ResourceWarning)
    warnings.filterwarnings("ignore", category=DeprecationWarning)


# =====================================================================
# Network & DNS Interception
# =====================================================================

_orig_getaddrinfo = socket.getaddrinfo
_orig_gethostbyname = socket.gethostbyname


def selective_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if host in ("127.0.0.1", "localhost", "::1", None, "") or port == 0:
        return _orig_getaddrinfo(host, port, family, type, proto, flags)
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port or 80))]


def selective_gethostbyname(host):
    if host in ("127.0.0.1", "localhost", "::1", ""):
        return _orig_gethostbyname(host)
    return "127.0.0.1"


@pytest.fixture(autouse=True)
def mock_external_network_calls():
    """Globally intercepts live DNS and HTTP requests."""
    with (
        patch("socket.gethostbyname", side_effect=selective_gethostbyname),
        patch("socket.getaddrinfo", side_effect=selective_getaddrinfo),
        patch("requests.get") as mock_get,
        patch("requests.post") as mock_post,
    ):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_response.text = ""

        mock_get.return_value = mock_response
        mock_post.return_value = mock_response

        yield


# =====================================================================
# Model & Pipeline Fixtures
# =====================================================================

@pytest.fixture
def mock_model():
    model = MagicMock()
    model.predict.return_value = [0]
    model.predict_proba.return_value = [[0.85, 0.15]]
    return model


@pytest.fixture
def shared_pipeline(mock_model):
    pipeline = MagicMock(spec=PhishingDetectionPipeline)
    pipeline.model = mock_model
    pipeline.model_loaded = True

    default_result = {
        "url": "http://example.com",
        "prediction": "legitimate",
        "is_phishing": False,
        "risk_score": 10.0,
        "confidence": 0.95,
        "confidence_score": 0.95,
        "model_score": 0.05,
        "risk_level": "LOW",
        "heuristics_triggered": [],
        "scanned_at": "2026-08-23T20:00:00Z",
        "scan_timestamp": "2026-08-23T20:00:00Z",
    }

    pipeline.inspect_url.return_value = default_result
    pipeline.analyze_url.return_value = default_result
    pipeline.inspect_batch.return_value = [default_result]
    pipeline.analyze_batch.return_value = [default_result]

    return pipeline


@pytest.fixture
def sample_phishing_result():
    return {
        "url": "http://login-verify-account-security-update.com",
        "prediction": "phishing",
        "is_phishing": True,
        "risk_score": 88.5,
        "confidence": 0.92,
        "confidence_score": 0.92,
        "model_score": 0.85,
        "risk_level": "CRITICAL",
        "heuristics_triggered": [
            {"rule": "SUSPICIOUS_KEYWORD", "weight": 25.0},
            {"rule": "TOO_MANY_SUBDOMAINS", "weight": 15.0},
        ],
        "scanned_at": "2026-08-23T20:00:00Z",
        "scan_timestamp": "2026-08-23T20:00:00Z",
    }


# =====================================================================
# Database Fixtures (In-Memory SQLite)
# =====================================================================

@pytest.fixture
def test_db_engine():
    """Creates an isolated, thread-shared in-memory SQLite engine for testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    db.Base.metadata.create_all(bind=engine)
    yield engine
    db.Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def db_session(test_db_engine):
    """Provides a transactional database session bound to the test engine."""
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=test_db_engine)
    ScopedSession = scoped_session(session_factory)
    session = ScopedSession()
    try:
        yield session
    finally:
        session.close()
        ScopedSession.remove()


@pytest.fixture
def mock_db_session():
    """Mock session for lightweight isolated unit tests (kept for legacy support)."""
    session = MagicMock()
    session.rollback.return_value = None
    session.commit.return_value = None
    session.add.return_value = None
    session.query.return_value.filter.return_value.all.return_value = []
    return session


@pytest.fixture
def sample_urls():
    return {
        "legitimate": [
            "https://www.google.com",
            "https://github.com/organization/repo",
            "https://en.wikipedia.org/wiki/Main_Page",
        ],
        "phishing": [
            "http://192.168.1.1/login.php",
            "http://paypal-security-update-account.com/verify",
            "http://secure.bankofamerica.login.user-auth-check.xyz",
        ],
        "malformed": [
            "",
            "   ",
            "not_a_url",
            "http://",
        ],
    }


# =====================================================================
# FastAPI Test Client Fixture
# =====================================================================

@pytest.fixture
def client(shared_pipeline, db_session):
    """FastAPI TestClient integrated with live in-memory DB session override."""
    from src.main import app

    def _override_get_db():
        try:
            yield db_session
        finally:
            pass

    # Swap the real DB dependency with our test session
    app.dependency_overrides[db.get_db] = _override_get_db

    with (
        patch("src.main.get_pipeline", return_value=shared_pipeline),
        patch("src.main._pipeline_instance", shared_pipeline),
        patch("src.main.check_db_health", return_value=True),
        patch("src.main.log_scan", return_value=True),
    ):
        with TestClient(app) as test_client:
            yield test_client

    # Clean up overrides post-test
    app.dependency_overrides.clear()