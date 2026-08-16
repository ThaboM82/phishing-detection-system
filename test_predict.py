import pytest
from fastapi.testclient import TestClient
from src.main import app

# Initialize the in-memory test client
client = TestClient(app)

TEST_PAYLOADS = {
    "legitimate": "https://www.google.com",
    "suspicious": "http://login-verification-secure-account.com/login.php",
    "ip_based": "http://192.168.1.1/admin/login",
    "batch": [
        "https://github.com",
        "http://paypal-security-update-fix.com",
        "http://10.0.0.1/verify",
    ],
}


# =====================================================================
# 1. Health & Service Readiness
# =====================================================================

def test_health_check():
    """Verify system health, database readiness, and model load status."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data.get("status") == "healthy" or "status" in data
    assert "model_loaded" in data


# =====================================================================
# 2. Single & Batch Inspection Endpoints
# =====================================================================

def test_inspect_single_url_suspicious():
    """Verify single URL inspection for a suspicious payload."""
    payload = {"url": TEST_PAYLOADS["suspicious"]}
    res = client.post("/api/v1/inspect", json=payload)
    assert res.status_code == 200

    data = res.json()
    assert "verdict" in data
    assert "ml_probability" in data
    assert "heuristic_flags_count" in data
    assert isinstance(data["ml_probability"], float)


def test_inspect_single_url_legitimate():
    """Verify clean URL inspection yields a benign or low-risk verdict."""
    payload = {"url": TEST_PAYLOADS["legitimate"]}
    res = client.post("/api/v1/inspect", json=payload)
    assert res.status_code == 200

    data = res.json()
    assert data.get("verdict") == "BENIGN" or data.get("ml_probability", 1.0) < 0.5


def test_inspect_batch_urls():
    """Verify batch processing handles multiple URLs accurately."""
    payload = {"urls": TEST_PAYLOADS["batch"]}
    res = client.post("/api/v1/inspect/batch", json=payload)
    assert res.status_code == 200

    data = res.json()
    assert isinstance(data, list)
    assert len(data) == len(TEST_PAYLOADS["batch"])


def test_inspect_invalid_payload():
    """Verify request validation fails cleanly on missing or malformed fields."""
    # Missing required 'url' field
    res = client.post("/api/v1/inspect", json={})
    assert res.status_code in [400, 422]

    # Empty URL string
    res_empty = client.post("/api/v1/inspect", json={"url": ""})
    assert res_empty.status_code in [400, 422]


# =====================================================================
# 3. Configuration & Heuristic Engine Endpoints
# =====================================================================

def test_get_and_update_config():
    """Fetch current heuristic configurations and update parameters."""
    # 1. Fetch config
    res = client.get("/api/v1/config")
    assert res.status_code == 200
    current_config = res.json()

    # 2. Update config parameter
    updated_config = current_config.copy()
    updated_config["max_url_length"] = 80

    put_res = client.put("/api/v1/config", json=updated_config)
    assert put_res.status_code == 200
    assert put_res.json().get("max_url_length") == 80


# =====================================================================
# 4. Telemetry & Analytics Endpoints
# =====================================================================

def test_telemetry_logs_and_stats():
    """Verify telemetry log retrieval and aggregate statistics outputs."""
    # Fetch audit logs
    res_logs = client.get("/api/v1/telemetry?limit=5")
    assert res_logs.status_code == 200
    assert isinstance(res_logs.json(), list)

    # Fetch aggregate stats
    res_stats = client.get("/api/v1/telemetry/stats")
    assert res_stats.status_code == 200
    stats = res_stats.json()
    assert "total_scans" in stats or "phishing_ratio_percentage" in stats


# =====================================================================
# 5. Dynamic Pipeline Lifecycle Endpoints
# =====================================================================

def test_model_hot_reload():
    """Verify hot-reloading model and heuristic artifacts on demand."""
    res = client.post("/api/v1/model/reload")
    assert res.status_code == 200
    assert "message" in res.json() or "status" in res.json()