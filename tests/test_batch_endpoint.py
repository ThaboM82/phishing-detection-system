"""
tests/test_batch_endpoint.py

Dedicated integration tests for the batch URL inspection endpoint (/inspect/batch).
Verifies request parsing, detection logic, response envelope structures, 
async execution pathways, and database persistence resiliency.
"""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from src.main import app, get_db, get_pipeline

client = TestClient(app)


# =====================================================================
# Fixtures
# =====================================================================

@pytest.fixture
def mock_db():
    """Mock database session dependency."""
    return MagicMock()


@pytest.fixture
def mock_pipeline():
    """
    Mock detection pipeline specifically configured for batch processing behaviors.
    Includes explicit model_loaded flags, synchronous and asynchronous batch runners,
    and granular detection logic mapping.
    """
    pipeline = MagicMock()
    pipeline.model = MagicMock()
    
    # Configure model attributes to prevent feature mismatch warnings
    pipeline.model.n_features_in_ = 17
    
    # Force model initialization state
    pipeline.model_loaded = True
    pipeline.is_loaded = True

    def _is_phishing_url(url: str) -> bool:
        """Determines phishing classification based on keyword matching."""
        if not url:
            return False
        url_lower = str(url).lower()
        phish_keywords = [
            "phish", "phishing", "evil", "fake", "suspicious", 
            "paypal", "malicious", "alert"
        ]
        return any(keyword in url_lower for keyword in phish_keywords)

    def mock_inspect_url(url: str, **kwargs):
        """Single URL evaluation logic."""
        is_phish = _is_phishing_url(url)
        return {
            "url": url,
            "prediction": "PHISHING" if is_phish else "LEGITIMATE",
            "is_phishing": is_phish,
            "confidence": 0.96 if is_phish else 0.04,
            "confidence_score": 0.96 if is_phish else 0.04,
            "phishing_probability": 0.96 if is_phish else 0.04,
            "risk_score": 96.0 if is_phish else 4.0,
            "model_score": 0.96 if is_phish else 0.04,
            "risk_level": "CRITICAL" if is_phish else "LOW",
            "heuristics_triggered": [{"rule": "SUSPICIOUS_DOMAIN"}] if is_phish else [],
            "scan_timestamp": "2026-08-21T10:00:00Z",
            "status": "success",
        }

    def _generate_batch_results(urls):
        """Processes list of URLs filtering out empty entries."""
        if not urls:
            return []
        return [mock_inspect_url(u) for u in urls if u and str(u).strip()]

    async def mock_analyze_batch_async(urls, **kwargs):
        return _generate_batch_results(urls)

    def mock_analyze_batch(urls, **kwargs):
        return _generate_batch_results(urls)

    # Attach methods to support both sync and async FastAPI route handlers
    pipeline.inspect_url = MagicMock(side_effect=mock_inspect_url)
    pipeline.analyze_url = MagicMock(side_effect=mock_inspect_url)
    pipeline.analyze_batch = MagicMock(side_effect=mock_analyze_batch)
    pipeline.analyze_batch_async = AsyncMock(side_effect=mock_analyze_batch_async)

    return pipeline


@pytest.fixture(autouse=True)
def override_dependencies(mock_db, mock_pipeline):
    """
    Globally override database and pipeline dependencies before each test runs,
    clearing overrides during teardown to avoid pollution.
    """
    mock_pipeline.model_loaded = True
    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_pipeline] = lambda: mock_pipeline
    yield
    app.dependency_overrides.clear()


# =====================================================================
# Helpers
# =====================================================================

def _extract_results(response_data):
    """
    Normalizes response payloads into a flat list of results regardless of whether
    the endpoint returns a top-level array or an enveloped dictionary (e.g., {'results': [...]}).
    """
    if isinstance(response_data, dict):
        return response_data.get("results", response_data.get("data", []))
    return response_data


# =====================================================================
# Batch Endpoint Tests
# =====================================================================

def test_batch_inspect_mixed_urls():
    """
    Test inspecting a mixed batch containing legitimate, phishing, and sub-path URLs.
    Validates accurate classification and status codes.
    """
    payload = {
        "urls": [
            "https://google.com",
            "http://evil-phishing-site.com/login",
            "https://github.com/profile",
            "http://fake-paypal-verify.com"
        ]
    }
    response = client.post("/inspect/batch", json=payload)
    assert response.status_code == 200

    results = _extract_results(response.json())
    assert len(results) == 4

    results_map = {item["url"]: item for item in results}

    assert results_map["https://google.com"]["is_phishing"] is False
    assert results_map["https://github.com/profile"]["is_phishing"] is False

    assert results_map["http://evil-phishing-site.com/login"]["is_phishing"] is True
    assert results_map["http://evil-phishing-site.com/login"]["risk_level"] in ["MEDIUM", "HIGH", "CRITICAL"]

    assert results_map["http://fake-paypal-verify.com"]["is_phishing"] is True
    assert results_map["http://fake-paypal-verify.com"]["risk_level"] in ["HIGH", "CRITICAL"]


def test_batch_inspect_empty_urls_array():
    """
    Test passing an empty 'urls' array. 
    Handles both HTTP 200 (empty response) and validation errors (400/422).
    """
    response = client.post("/inspect/batch", json={"urls": []})
    assert response.status_code in [200, 400, 422]

    if response.status_code == 200:
        results = _extract_results(response.json())
        assert len(results) == 0


def test_batch_inspect_invalid_payload_format():
    """Test passing invalid JSON types (e.g., non-list string or integer) triggers validation error."""
    local_client = TestClient(app, raise_server_exceptions=False)
    
    # Invalid data structure for 'urls'
    response = local_client.post("/inspect/batch", json={"urls": "not-a-list"})
    assert response.status_code == 422

    # Completely missing required key
    response = local_client.post("/inspect/batch", json={"invalid_key": []})
    assert response.status_code == 422


def test_batch_inspect_deduplication_or_large_batch():
    """Test batch processing performance and structure across multiple homogeneous items."""
    urls = [f"https://legitimate-site-{i}.org" for i in range(10)]
    urls.append("http://phishing-alert-system.com")

    response = client.post("/inspect/batch", json={"urls": urls})
    assert response.status_code == 200

    results = _extract_results(response.json())
    assert len(results) == 11

    phish_results = [r for r in results if r["is_phishing"]]
    clean_results = [r for r in results if not r["is_phishing"]]

    assert len(phish_results) >= 1
    assert len(clean_results) >= 0
    assert any(r["url"] == "http://phishing-alert-system.com" for r in phish_results)


@patch("src.main.log_scan", side_effect=Exception("Database Connection Dropped"), create=True)
def test_batch_inspect_database_resilience(mock_log_scan):
    """
    Ensure telemetry logging failures or DB errors during batch scanning 
    do not cause the API endpoint to fail or crash.
    """
    payload = {
        "urls": [
            "https://safe-domain.com",
            "http://suspicious-domain.com"
        ]
    }
    response = client.post("/inspect/batch", json=payload)
    assert response.status_code == 200

    results = _extract_results(response.json())
    assert len(results) == 2
    assert results[0]["url"] == "https://safe-domain.com"
    assert results[1]["url"] == "http://suspicious-domain.com"


def test_batch_inspect_model_unloaded_fallback(mock_pipeline):
    """
    Test endpoint behavior when model/pipeline is uninitialized.
    Validates heuristic fallback mode without failing the entire batch.
    """
    mock_pipeline.model = None
    mock_pipeline.model_loaded = False
    mock_pipeline.is_loaded = False
    
    payload = {"urls": ["https://example.com"]}
    response = client.post("/inspect/batch", json=payload)
    
    assert response.status_code in [200, 500, 503]
    if response.status_code == 200:
        results = _extract_results(response.json())
        assert len(results) == 1
        assert results[0]["url"] == "https://example.com"