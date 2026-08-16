import pytest
from src.pipeline import evaluate_url, evaluate_url_batch
from src.heuristics import DEFAULT_CONFIG


def _extract_rule_names(fired_rules):
    """
    Helper function to safely extract rule name strings regardless of whether
    fired_rules contains raw strings or dictionary structures.
    """
    if not fired_rules:
        return []
    return [r["rule"] if isinstance(r, dict) else r for r in fired_rules]


# =====================================================================
# 1. Core URL Inspection Tests
# =====================================================================

def test_clean_url():
    """Verify clean, high-reputation domain returns a BENIGN verdict and low probability."""
    result = evaluate_url("https://www.google.com")
    
    assert result["verdict"] == "BENIGN"
    assert "ml_probability" in result
    assert result["ml_probability"] < 0.5
    assert "flags_count" in result
    assert result["flags_count"] == 0
    assert result.get("heuristic_flags_count") == 0  # Compatibility check
    assert len(result.get("fired_rules", [])) == 0


def test_ip_hostname_detection():
    """Verify raw IP addresses trigger IP-based heuristics and increment flags."""
    url = "http://192.168.1.1/login"
    result = evaluate_url(url)
    
    rule_names = _extract_rule_names(result.get("fired_rules", []))
    
    assert result["flags_count"] > 0
    assert any("IP" in str(rule).upper() or "IP_HOSTNAME" in str(rule).upper() for rule in rule_names) or result["verdict"] in ["SUSPICIOUS", "BLOCKED", "PHISHING"]


def test_suspicious_keywords_and_brand_spoofing():
    """Verify brand spoofing and security keywords trigger heuristic warnings and non-BENIGN verdicts."""
    url = "http://paypal-security-update-verify-account.com/login.php"
    result = evaluate_url(url)
    
    assert "fired_rules" in result
    assert "ml_probability" in result
    assert result["flags_count"] > 0
    assert result["verdict"] in ["SUSPICIOUS", "BLOCKED", "PHISHING"]


def test_excessive_url_length_rule():
    """Verify extremely long URLs trigger length-based heuristics."""
    long_url = "http://example.com/" + "a" * 250 + "/login"
    result = evaluate_url(long_url)
    
    rule_names = _extract_rule_names(result.get("fired_rules", []))
    assert result["flags_count"] > 0
    assert any("LENGTH" in str(r).upper() or "LONG" in str(r).upper() for r in rule_names)


# =====================================================================
# 2. Edge Case & Input Validation Tests
# =====================================================================

def test_empty_url_raises_value_error():
    """Verify evaluate_url handles or raises error when given an empty string."""
    with pytest.raises((ValueError, AttributeError)):
        evaluate_url("")


def test_malformed_url_handling():
    """Verify pipeline handles poorly structured or arbitrary strings gracefully without crashing."""
    malformed_url = "not_a_valid_url_structure"
    result = evaluate_url(malformed_url)
    
    assert "verdict" in result
    assert "ml_probability" in result
    assert "flags_count" in result


# =====================================================================
# 3. Batch Inspection & Configuration Sync Tests
# =====================================================================

def test_batch_inspection():
    """Verify batch execution processes multiple clean and suspicious URLs accurately."""
    urls = [
        "https://www.google.com",
        "http://10.0.0.1/admin",
        "http://secure-bank-login-update.com/verify"
    ]
    
    results = evaluate_url_batch(urls)
        
    assert len(results) == 3
    assert results[0]["verdict"] == "BENIGN"
    assert results[1]["flags_count"] > 0 or results[1]["verdict"] != "BENIGN"
    assert results[2]["verdict"] in ["SUSPICIOUS", "BLOCKED", "PHISHING"]


def test_dynamic_config_update():
    """Verify passing modified config (e.g. max URL length) alters heuristic evaluation."""
    custom_config = DEFAULT_CONFIG.copy()
    custom_config["max_url_length"] = 30
    
    test_url = "http://this-is-a-medium-length-testing-domain-string.com"
    result = evaluate_url(test_url, config=custom_config)
    
    rule_names = _extract_rule_names(result.get("fired_rules", []))
    assert result["flags_count"] > 0
    assert any("LENGTH" in str(r).upper() or "LONG" in str(r).upper() for r in rule_names)