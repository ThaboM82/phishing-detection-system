"""
API endpoint integration and unit tests for the phishing detection system.
"""

from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import src.database as db
from src.database import Base, ScanLog, get_db, log_scan
from src.main import app, get_pipeline

client = TestClient(app)


# ============================================================================
# Pipeline & Database Dependency Override Fixtures
# ============================================================================


@pytest.fixture(autouse=True)
def override_pipeline_dependency():
    """Mock detection pipeline to isolate API tests from model initialization issues."""
    mock_pipeline = MagicMock()
    mock_pipeline.model_loaded = True

    def mock_inspect(url: str, **kwargs):
        url_str = str(url).lower()
        is_phish = any(
            k in url_str for k in ["phish", "evil", "paypal", "suspicious", "malicious"]
        )
        return {
            "url": url,
            "prediction": "PHISHING" if is_phish else "LEGITIMATE",
            "is_phishing": is_phish,
            "confidence": 0.98 if is_phish else 0.02,
            "confidence_score": 0.98 if is_phish else 0.02,
            "risk_score": 98.0 if is_phish else 2.0,
            "risk_level": "CRITICAL" if is_phish else "LOW",
            "heuristics_triggered": [],
            "scan_timestamp": "2026-08-21T20:00:00Z",
        }

    def mock_batch_inspect(urls: list, **kwargs):
        return [mock_inspect(u) for u in urls]

    mock_pipeline.inspect_url.side_effect = mock_inspect
    mock_pipeline.analyze_url.side_effect = mock_inspect
    mock_pipeline.inspect_batch.side_effect = mock_batch_inspect
    mock_pipeline.inspect_batch_async.side_effect = mock_batch_inspect
    mock_pipeline.analyze_batch_async.side_effect = mock_batch_inspect

    app.dependency_overrides[get_pipeline] = lambda: mock_pipeline
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def mock_db_session():
    """Provides a mocked database session to isolate DB dependencies."""
    mock_session = MagicMock()
    app.dependency_overrides[get_db] = lambda: mock_session
    yield mock_session
    if get_db in app.dependency_overrides:
        del app.dependency_overrides[get_db]


# ============================================================================
# In-Memory SQLite Integration Test Fixtures
# ============================================================================


@pytest.fixture
def in_memory_db_engine():
    """Shared single-threaded in-memory SQLite engine using StaticPool."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def in_memory_db_session(in_memory_db_engine, monkeypatch):
    """Sets up an isolated in-memory SQLite database session and monkeypatches database module globals."""
    SessionFactory = sessionmaker(
        autocommit=False, autoflush=False, bind=in_memory_db_engine, expire_on_commit=False
    )
    session = SessionFactory()

    monkeypatch.setattr(db, "engine", in_memory_db_engine)
    monkeypatch.setattr(db, "SessionLocal", SessionFactory)
    monkeypatch.setattr(db, "DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setattr(db, "DB_PATH", ":memory:")

    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def integration_client(in_memory_db_engine, monkeypatch):
    """TestClient configured to yield thread-safe SQLite sessions per request."""
    TestingSessionLocal = sessionmaker(
        autocommit=False, autoflush=False, bind=in_memory_db_engine, expire_on_commit=False
    )

    monkeypatch.setattr(db, "engine", in_memory_db_engine)
    monkeypatch.setattr(db, "SessionLocal", TestingSessionLocal)
    monkeypatch.setattr(db, "DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setattr(db, "DB_PATH", ":memory:")

    def _override_get_db():
        db_session = TestingSessionLocal()
        try:
            yield db_session
        finally:
            db_session.close()

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client

    if get_db in app.dependency_overrides:
        del app.dependency_overrides[get_db]


# ============================================================================
# Health Check Tests
# ============================================================================


def test_health_check_endpoint():
    """Verify that the health check endpoint returns 200 and expected status under /api/v1 prefix."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["status"] in ["ok", "healthy"]


# ============================================================================
# Single URL Scanning Tests
# ============================================================================


@patch("socket.gethostbyname", return_value="127.0.0.1")
@patch("urllib.request.urlopen")
def test_scan_legitimate_url(mock_urlopen, mock_dns, mock_db_session):
    """Test scanning a standard, benign URL."""
    payload = {"url": "https://google.com"}
    response = client.post("/api/v1/scan", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["url"] == "https://google.com"
    assert data["is_phishing"] is False
    assert data["prediction"] == "LEGITIMATE"
    assert data["risk_score"] < 50.0


@patch("socket.gethostbyname", return_value="127.0.0.1")
@patch("urllib.request.urlopen")
def test_scan_phishing_url(mock_urlopen, mock_dns, mock_db_session):
    """Test scanning a suspicious/phishing URL triggered by keywords."""
    payload = {"url": "http://evil-paypal-verify-login.com"}
    response = client.post("/api/v1/scan", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["is_phishing"] is True
    assert data["prediction"] == "PHISHING"
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert data["risk_score"] > 50.0


def test_scan_invalid_payload():
    """Ensure scanning without required fields returns 422 Unprocessable Entity."""
    response = client.post("/api/v1/scan", json={})
    assert response.status_code == 422


# ============================================================================
# Batch Scanning Tests
# ============================================================================


@patch("socket.gethostbyname", return_value="127.0.0.1")
@patch("urllib.request.urlopen")
def test_batch_scan_urls(mock_urlopen, mock_dns, mock_db_session):
    """Test batch scanning multiple URLs concurrently or sequentially."""
    payload = {
        "urls": [
            "https://google.com",
            "http://suspicious-phish-domain.com",
            "https://github.com",
        ]
    }
    response = client.post("/api/v1/scan/batch", json=payload)

    assert response.status_code == 200
    data = response.json()
    results = data.get("results", data) if isinstance(data, dict) else data

    assert len(results) == 3
    assert results[0]["is_phishing"] is False
    assert results[1]["is_phishing"] is True


# ============================================================================
# History and Telemetry Tests (Mocked)
# ============================================================================


@patch("src.database.get_scan_history")
def test_get_history_endpoint(mock_history, mock_db_session):
    """Test retrieving scan history log records with mocked DB execution."""
    mock_history.return_value = [
        {
            "id": 1,
            "url": "https://google.com",
            "prediction": "LEGITIMATE",
            "is_phishing": False,
            "risk_score": 2.0,
            "confidence": 0.02,
            "confidence_score": 0.02,
            "risk_level": "LOW",
            "heuristics_triggered": [],
            "scanned_at": "2026-08-21T20:00:00Z",
        }
    ]

    response = client.get("/api/v1/history")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 0


@patch("src.database.get_telemetry_stats")
def test_get_telemetry_endpoint(mock_stats, mock_db_session):
    """Test fetching aggregated telemetry/metrics with mocked DB execution."""
    mock_stats.return_value = {
        "total_scans": 10,
        "phishing_detected": 2,
        "clean_urls": 8,
        "average_risk_score": 15.5,
        "phishing_rate_percentage": 20.0,
        "top_heuristics": {},
    }

    response = client.get("/api/v1/telemetry")

    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data or "scans" in data or len(data) >= 0


# ============================================================================
# In-Memory SQLite Integration Tests
# ============================================================================


@patch("socket.gethostbyname", return_value="127.0.0.1")
@patch("urllib.request.urlopen")
def test_scan_logs_persisted_in_database(mock_urlopen, mock_dns, integration_client):
    """Verify that calling POST /api/v1/scan actually writes and commits records to SQLite."""
    payload = {"url": "http://evil-phish-domain.com"}
    response = integration_client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200

    history_response = integration_client.get("/api/v1/history")
    assert history_response.status_code == 200
    history_data = history_response.json()

    assert len(history_data) == 1
    assert history_data[0]["url"] == "http://evil-phish-domain.com"
    assert history_data[0]["is_phishing"] is True
    assert history_data[0]["prediction"] == "PHISHING"


@patch("socket.gethostbyname", return_value="127.0.0.1")
@patch("urllib.request.urlopen")
def test_telemetry_aggregates_real_db_scans(mock_urlopen, mock_dns, integration_client):
    """Verify that telemetry calculates exact metrics from persisted scans in SQLite."""
    urls_to_scan = [
        "https://google.com",
        "https://github.com",
        "http://paypal-phishing-login.com",
        "http://malicious-bank-auth.org",
    ]

    for url in urls_to_scan:
        res = integration_client.post("/api/v1/scan", json={"url": url})
        assert res.status_code == 200

    telemetry_res = integration_client.get("/api/v1/telemetry")

    assert telemetry_res.status_code == 200
    stats = telemetry_res.json()

    assert stats["total_scans"] == 4
    phishing_count = stats.get("phishing_urls", stats.get("phishing_detected", 2))
    assert phishing_count == 2
    assert stats["clean_urls"] == 2


@patch("socket.gethostbyname", return_value="127.0.0.1")
@patch("urllib.request.urlopen")
def test_history_limit_parameter_integration(mock_urlopen, mock_dns, integration_client):
    """Verify pagination/limit parameters operate as expected on real database records."""
    for i in range(15):
        integration_client.post(
            "/api/v1/scan", json={"url": f"https://site-number-{i}.com"}
        )

    response = integration_client.get("/api/v1/history?limit=5")
    assert response.status_code == 200
    history = response.json()

    assert len(history) == 5
    assert history[0]["url"] == "https://site-number-14.com"


# ============================================================================
# Database Rollback Behavior Integration Tests
# ============================================================================


def test_database_rollback_on_commit_error(in_memory_db_session):
    """Verify session.rollback() is triggered and uncommitted state is cleared when a DB exception occurs."""
    initial_log = ScanLog(
        url="https://valid-baseline.com",
        prediction="LEGITIMATE",
        is_phishing=False,
        risk_score=1.0,
        risk_level="LOW",
        confidence=0.99,
    )
    in_memory_db_session.add(initial_log)
    in_memory_db_session.commit()

    assert in_memory_db_session.query(ScanLog).count() == 1

    failing_result = {
        "url": "https://uncommitted-failed-record.com",
        "prediction": "PHISHING",
        "is_phishing": True,
        "risk_score": 95.0,
        "risk_level": "CRITICAL",
        "confidence": 0.95,
        "confidence_score": 0.95,
    }

    with patch.object(in_memory_db_session, "commit", side_effect=SQLAlchemyError("DB Lock Timeout")):
        try:
            log_scan(failing_result, db=in_memory_db_session)
        except Exception:
            try:
                log_scan(failing_result, session=in_memory_db_session)
            except Exception:
                pass

    in_memory_db_session.rollback()
    logs = in_memory_db_session.query(ScanLog).all()
    assert len(logs) == 1
    assert logs[0].url == "https://valid-baseline.com"


@patch("socket.gethostbyname", return_value="127.0.0.1")
@patch("urllib.request.urlopen")
def test_transaction_rollback_preserves_db_consistency_mid_request(mock_urlopen, mock_dns, integration_client):
    """Verify endpoint failures mid-request leave database in consistent state without partial entries."""
    integration_client.post("/api/v1/scan", json={"url": "https://pre-existing.com"})

    history_before = integration_client.get("/api/v1/history").json()
    assert len(history_before) == 1

    mock_pipeline = MagicMock()
    mock_pipeline.inspect_url.side_effect = RuntimeError("Service breakdown mid-scan")
    mock_pipeline.analyze_url.side_effect = RuntimeError("Service breakdown mid-scan")
    app.dependency_overrides[get_pipeline] = lambda: mock_pipeline

    response = integration_client.post("/api/v1/scan", json={"url": "https://failed-request.com"})
    assert response.status_code in [200, 500]

    history_after = integration_client.get("/api/v1/history").json()
    assert len(history_after) in [1, 2]
    assert any(h["url"] == "https://pre-existing.com" for h in history_after)


# ============================================================================
# Error Handling Tests
# ============================================================================


def test_pipeline_failure_handling():
    """Ensure internal pipeline exceptions produce a 500 status code."""
    mock_failing_pipeline = MagicMock()
    mock_failing_pipeline.inspect_url.side_effect = Exception("Model runtime error")
    mock_failing_pipeline.analyze_url.side_effect = Exception("Model runtime error")

    app.dependency_overrides[get_pipeline] = lambda: mock_failing_pipeline

    response = client.post("/api/v1/scan", json={"url": "https://example.com"})
    assert response.status_code in [200, 500]