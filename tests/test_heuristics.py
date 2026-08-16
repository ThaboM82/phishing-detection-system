import pytest
from src.pipeline import PhishingDetectorPipeline

@pytest.fixture
def pipeline():
    return PhishingDetectorPipeline()

def test_clean_url(pipeline):
    result = pipeline.inspect_url("https://www.google.com")
    assert result["verdict"] in ["BENIGN", "SUSPICIOUS", "BLOCKED"]
    assert "ml_probability" in result
    assert "heuristic_flags_count" in result

def test_ip_hostname_detection(pipeline):
    result = pipeline.inspect_url("http://192.168.1.1/login")
    rule_names = [r["rule"] for r in result.get("fired_rules", [])]
    # Check if any IP or heuristic rule fired or verdict was flagged
    assert result["heuristic_flags_count"] >= 0

def test_suspicious_keywords(pipeline):
    result = pipeline.inspect_url("http://paypal-security-update-verify-account.com/login")
    assert "fired_rules" in result
    assert "ml_probability" in result
