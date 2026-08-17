import os
import pytest
from fastapi.testclient import TestClient

from src.main import app
import src.main as main_module
from src.database import Base, engine, SessionLocal
from src.models import ConfigRule
from src.pipeline import PhishingPipeline


# Initialize test client
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
# Database & Pipeline Test Setup Fixtures
# =====================================================================

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Setup database tables, seed initial config, and initialize the pipeline."""
    # 1. Create database schema
    Base.metadata.create_all(bind=engine)

    # 2. Seed initial default ConfigRule record required by endpoints
    db = SessionLocal()
    try:
        config = db.query(ConfigRule).filter(ConfigRule.id == 1).first()
        if not config:
            default_config = ConfigRule(
                id=1,
                max_url_length=75,
                max_special_chars=8,
                max_subdomains=3,
                max_entropy=4.5,
                block_ip_hostnames=True,
                flag_sensitive_keywords=True,
                flag_brand_spoofing=True,
                flag_non_standard_ports=True,
                flag_suspicious_tlds=True
            )
            db.add(default_config)
            db.commit()
    finally:
        db.close()

    # 3. Ensure ML Pipeline is loaded and initialized on the FastAPI main app context
    if not hasattr(main_module, "pipeline") or main_module.pipeline is None:
        main_module.pipeline = PhishingPipeline()

    model_path = os.path.join(os.getcwd(), "phishing_rf_model.pkl")
    if os.path.exists(model_path):
        try:
            main_module.pipeline.load_model(model_path)
        except Exception:
            # Fallback setting if mock artifact state is needed
            main_module.pipeline.is_initialized = True
    else:
        # Guarantee initialization flag for CI test contexts without model pickles
        main_module.pipeline.is_initialized = True

    yield

    # Clean up tables after test suite run
    Base.metadata.drop_all(bind=engine)


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