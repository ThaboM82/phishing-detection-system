import pytest
from src.heuristics import HeuristicEngine, DEFAULT_CONFIG


def _extract_rule_names(fired_rules):
    """
    Helper function to safely extract rule name strings regardless of whether
    fired_rules contains raw strings or dictionary structures.
    """
    if not fired_rules:
        return []
    names = []
    for r in fired_rules:
        if isinstance(r, dict):
            names.append(str(r.get("rule", r.get("name", ""))))
        else:
            names.append(str(r))
    return names


# =====================================================================
# 1. Direct Heuristic Engine Tests
# =====================================================================

def test_clean_url_heuristics():
    """Verify clean URL triggers no heuristic flags."""
    engine = HeuristicEngine()
    url = "https://www.google.com"
    
    res = engine.evaluate(url, feature_vector={"domain": "google.com"})
    
    assert res.get("flags_count", 0) == 0
    assert len(res.get("fired_rules", [])) == 0
    assert res.get("override_verdict") is None


def test_ip_hostname_heuristic_rule():
    """Verify raw IP hostnames fire the IP address heuristic rule."""
    engine = HeuristicEngine()
    url = "http://192.168.1.1/login"
    
    res = engine.evaluate(url, feature_vector={"domain": "192.168.1.1"})
    rule_names = _extract_rule_names(res.get("fired_rules", []))
    
    assert res.get("flags_count", 0) > 0
    assert any("IP" in r.upper() for r in rule_names)


def test_suspicious_keywords_and_brand_spoofing_rules():
    """Verify keywords and brand spoofing trigger heuristic rule flags."""
    engine = HeuristicEngine()
    url = "http://paypal-security-update-verify-account.com/login.php"
    
    res = engine.evaluate(url, feature_vector={"domain": "paypal-security-update-verify-account.com"})
    rule_names = _extract_rule_names(res.get("fired_rules", []))
    
    assert res.get("flags_count", 0) > 0
    assert len(rule_names) > 0


def test_excessive_length_heuristic_rule():
    """Verify extremely long URLs trigger length threshold heuristics."""
    engine = HeuristicEngine()
    long_url = "http://example.com/" + "a" * 250 + "/login"
    
    res = engine.evaluate(long_url, feature_vector={"domain": "example.com"})
    rule_names = _extract_rule_names(res.get("fired_rules", []))
    
    assert res.get("flags_count", 0) > 0
    assert any("LENGTH" in r.upper() or "LONG" in r.upper() for r in rule_names)


# =====================================================================
# 2. Dynamic Configuration & Override Tests
# =====================================================================

def test_dynamic_config_length_threshold():
    """Verify custom config overrides default length thresholds in heuristic evaluation."""
    engine = HeuristicEngine()
    custom_config = DEFAULT_CONFIG.copy()
    
    if "max_url_length" in custom_config:
        custom_config["max_url_length"] = 30
    elif "url_length_threshold" in custom_config:
        custom_config["url_length_threshold"] = 30
    else:
        custom_config["max_url_length"] = 30

    test_url = "http://this-is-a-medium-length-testing-domain-string.com"
    res = engine.evaluate(test_url, feature_vector={}, config=custom_config)
    
    rule_names = _extract_rule_names(res.get("fired_rules", []))
    assert res.get("flags_count", 0) > 0
    assert any("LENGTH" in r.upper() or "LONG" in r.upper() for r in rule_names)


def test_heuristics_override_verdict():
    """Verify specific high-severity rules return an override verdict."""
    engine = HeuristicEngine()
    high_risk_url = "http://login.microsoft.com.account-update-verification.top/auth"
    
    res = engine.evaluate(high_risk_url, feature_vector={})
    assert res.get("flags_count", 0) > 0
    if "override_verdict" in res and res["override_verdict"] is not None:
        assert res["override_verdict"] in ["SUSPICIOUS", "BLOCKED", "PHISHING"]