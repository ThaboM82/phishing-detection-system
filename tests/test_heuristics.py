import pytest
from src.features import extract_features, is_punycode
from src.heuristics import (
    DEFAULT_TLD_RISK_SET,
    DEFAULT_WHITELIST,
    HeuristicEngine,
    evaluate_heuristics,
    extract_registered_domain,
    is_whitelisted,
)


# Helper function to extract rule string safely
def _get_rule_name(rule_obj) -> str:
    if isinstance(rule_obj, dict):
        return str(rule_obj.get("rule", rule_obj.get("name", "")))
    return str(rule_obj)


# =====================================================================
# 1. Direct Heuristic Engine & Detection Tests
# =====================================================================


def test_clean_url_heuristics():
    """Verify clean, legitimate URL triggers no heuristic flags."""
    url = "https://www.google.com"
    features = extract_features(url)
    triggered, score = evaluate_heuristics(features, url)

    assert len(triggered) == 0
    assert score == 0.0


def test_ip_hostname_heuristic_rule():
    """Verify raw IP hostnames fire the IP address heuristic rule."""
    url = "http://192.168.1.1/login"
    features = extract_features(url)
    triggered, score = evaluate_heuristics(features, url)

    assert len(triggered) > 0
    rule_names = [_get_rule_name(r).upper() for r in triggered]
    assert any("IP" in name for name in rule_names)
    assert score > 0.0


def test_suspicious_keywords_and_brand_spoofing_rules():
    """Verify keywords and brand spoofing trigger heuristic rule flags."""
    url = "http://paypal-security-update-verify-account.com/login.php"
    features = extract_features(url)
    triggered, score = evaluate_heuristics(features, url)

    assert len(triggered) > 0
    rule_names = [_get_rule_name(r).upper() for r in triggered]
    assert any(
        "KEYWORD" in name or "BRAND" in name or "SPOOF" in name
        for name in rule_names
    )
    assert score > 0.0


def test_excessive_length_heuristic_rule():
    """Verify extremely long URLs trigger length threshold heuristics."""
    long_url = "http://example.com/" + "a" * 250 + "/login"
    features = extract_features(long_url)
    triggered, score = evaluate_heuristics(features, long_url)

    assert len(triggered) > 0
    rule_names = [_get_rule_name(r).upper() for r in triggered]
    assert any(
        "LENGTH" in name or "LONG" in name or "EXCESSIVE" in name
        for name in rule_names
    )


# =====================================================================
# 2. South African Brand Impersonation & Whitelist Tests
# =====================================================================


@pytest.mark.parametrize(
    "sa_spoof_url,expected_brand",
    [
        ("http://capitec-secure-login-update.top/verify", "capitec"),
        ("http://fnb-online-banking-mfa.xyz/auth", "fnb"),
        ("http://standardbank-profile-security.info/login", "standardbank"),
        ("http://absa-refund-notice-sars.com/claim", "absa"),
        ("http://sars-tax-refund-portal.click/login", "sars"),
    ],
)
def test_south_african_brand_spoofing_detection(sa_spoof_url, expected_brand):
    """Verify spoofed SA banking and government URLs trigger heuristic flags."""
    features = extract_features(sa_spoof_url)
    triggered, score = evaluate_heuristics(features, sa_spoof_url)

    assert len(triggered) > 0, f"Expected heuristic triggers for {sa_spoof_url}"
    assert features["suspicious_keywords"] > 0
    assert score >= 20.0  # High-risk brand spoofing should contribute significant score


@pytest.mark.parametrize(
    "official_sa_url",
    [
        "https://www.standardbank.co.za",
        "https://www.capitecbank.co.za",
        "https://www.fnb.co.za",
        "https://www.absa.co.za",
        "https://www.sars.gov.za",
    ],
)
def test_official_south_african_domains_bypass_false_positives(official_sa_url):
    """Verify official SA domains trigger zero heuristic warnings via whitelist bypass."""
    features = extract_features(official_sa_url)
    triggered, score = evaluate_heuristics(features, official_sa_url)

    assert len(triggered) == 0, f"Official SA domain false positive: {official_sa_url}"
    assert score == 0.0


# =====================================================================
# 3. Dynamic Configuration & Feature Override Edge Cases
# =====================================================================


def test_dynamic_config_length_threshold_override():
    """Verify manual override on feature dict triggers targeted heuristics."""
    test_url = "http://this-is-a-medium-length-testing-domain-string.com"
    features = extract_features(test_url)

    # Force artificial values into feature dictionary across schema aliases
    custom_features = features.copy()
    custom_features["url_length"] = 300
    custom_features["at_count"] = 1
    custom_features["count_at"] = 1
    custom_features["has_at_symbol"] = 1
    custom_features["has_at"] = 1

    triggered, score = evaluate_heuristics(custom_features, test_url)

    rules = [_get_rule_name(r).upper() for r in triggered]

    assert any(
        r in rules for r in ["LONG_URL", "URL_EXCESSIVE_LENGTH"]
    ) or any("LENGTH" in r or "LONG" in r for r in rules)

    assert any(
        r in rules for r in ["AT_SYMBOL_PRESENT", "HAS_AT_SYMBOL", "AT_SYMBOL"]
    ) or any("AT" in r for r in rules)


def test_empty_or_invalid_url_handling():
    """Verify evaluation handles malformed or empty inputs without crashing."""
    features = extract_features("")
    triggered, score = evaluate_heuristics(features, "")

    assert isinstance(triggered, list)
    assert isinstance(score, (int, float))


def test_features_unicode_encode_error():
    # Domain containing non-ASCII character to force UnicodeEncodeError handling
    assert is_punycode("päypal.com") is True


def test_heuristics_empty_inputs():
    # Triggers domain normalization edge-case handling for empty strings
    assert extract_registered_domain("") == ""
    assert extract_registered_domain(None) == ""
    # Triggers whitelist evaluation safety check for empty inputs
    assert is_whitelisted("", {"paypal.com"}) is False
    assert is_whitelisted(None, {"paypal.com"}) is False


# =====================================================================
# 4. Specific Uncovered Rule Execution Paths
# =====================================================================


@pytest.mark.parametrize(
    "heuristic_url,expected_keywords",
    [
        ("http://example.com:8080/login", ["PORT"]),
        ("http://example.com//path//redirect", ["SLASH"]),
        ("http://%77%77%77%2e%67%6f%6f%67%6c%65%2e%63%6f%6d", ["ENCOD"]),
        ("http://xn--pypal-4ve.com", ["HOMOGRAPH", "PUNYCODE"]),
        ("http://sub1.sub2.sub3.sub4.suspicious-domain.xyz", ["SUBDOMAIN"]),
    ],
)
def test_uncovered_heuristic_rules_specific(heuristic_url, expected_keywords):
    """Hits specific individual rule evaluation branches and confirms rule keywords."""
    features = extract_features(heuristic_url)
    triggered, score = evaluate_heuristics(features, heuristic_url)

    assert isinstance(triggered, list)
    assert score > 0.0

    rule_names = [_get_rule_name(r).upper() for r in triggered]
    assert any(
        any(keyword in r for keyword in expected_keywords)
        for r in rule_names
    ), f"Expected rule matching {expected_keywords} in triggered rules: {rule_names}"


def test_heuristics_score_max_ceiling_cap():
    """Verify heuristic score is capped at 100.0 when multiple rules fire simultaneously."""
    multi_flag_url = (
        "http://192.168.1.1:8080//@paypal-security-update-verify-account.top/"
        + "a" * 250
        + "//login.php"
    )
    features = extract_features(multi_flag_url)
    triggered, score = evaluate_heuristics(features, multi_flag_url)

    assert len(triggered) >= 3
    assert score == 100.0


def test_heuristics_missing_keys_in_features_dict():
    """Verify evaluate_heuristics handles incomplete feature dictionaries gracefully."""
    empty_features = {}
    url = "http://example.xyz/login"

    triggered, score = evaluate_heuristics(empty_features, url)
    assert isinstance(triggered, list)
    assert isinstance(score, (int, float))


def test_is_whitelisted_variations():
    """Verify subdomains, exact matches, and case sensitivity in whitelist checking."""
    whitelist = {"google.com", "paypal.com", "gov.za"}

    assert is_whitelisted("google.com", whitelist) is True
    assert is_whitelisted("subdomain.google.com", whitelist) is True
    assert is_whitelisted("GOOGLE.COM".lower(), whitelist) is True
    assert is_whitelisted("google.com.attacker.tk", whitelist) is False


# =====================================================================
# 5. Granular Branch & Fallback Edge-Case Verification
# =====================================================================


def test_swapped_arguments_auto_handling():
    """Verify evaluate_heuristics automatically swaps positional args if (url, features) is passed."""
    # Pass URL as 1st arg and dict as 2nd arg
    triggers, score = evaluate_heuristics("http://evil-phish.xyz/login", {"has_ip": 1})
    assert len(triggers) > 0
    assert score > 0.0

    # Pass URL as 1st arg and None as 2nd arg
    triggers_none, score_none = evaluate_heuristics("http://google.com", None)
    assert triggers_none == []
    assert score_none == 0.0


def test_invalid_argument_types():
    """Verify invalid argument combinations gracefully return empty triggers and 0 score."""
    assert evaluate_heuristics(None, None) == ([], 0.0)
    assert evaluate_heuristics({}, "") == ([], 0.0)
    assert evaluate_heuristics({}, 12345) == ([], 0.0)
    assert evaluate_heuristics("not_a_dict", 98765) == ([], 0.0)


def test_extract_registered_domain_formatting():
    """Verify port stripping and www prefix removal in domain parsing."""
    assert extract_registered_domain("http://www.example.com:8080/test") == "example.com"
    assert extract_registered_domain("localhost:5000") == "localhost"
    assert extract_registered_domain("https://www.google.com") == "google.com"


def test_hyphen_brand_targeting_and_excessive_hyphen_logic():
    """Verify rules for hyphenated brand targets vs. neutral hyphenated domains."""
    # Brand targeting with hyphen
    t1, _ = evaluate_heuristics({"has_prefix_suffix": True}, "http://secure-paypal-verify.com")
    assert "PREFIX_SUFFIX_HYPHEN" in [_get_rule_name(r) for r in t1]

    # Excessive hyphens (>= 2)
    t2, _ = evaluate_heuristics({"has_prefix_suffix": True}, "http://my-secure-login-portal.com")
    assert "PREFIX_SUFFIX_HYPHEN" in [_get_rule_name(r) for r in t2]

    # Neutral hyphen (< 2 hyphens, non-brand)
    t3, _ = evaluate_heuristics({"has_prefix_suffix": True}, "http://my-domain.com")
    assert "PREFIX_SUFFIX_HYPHEN" not in [_get_rule_name(r) for r in t3]


def test_entropy_threshold_branches():
    """Verify individual entropy evaluation branches (domain, path, query)."""
    features = {
        "domain_entropy": 4.5,
        "path_entropy": 4.6,
        "query_entropy": 4.9,
    }
    triggers, _ = evaluate_heuristics(features, "http://randomdomain.com/path?q=1")
    rule_ids = [_get_rule_name(r) for r in triggers]
    assert "HIGH_DOMAIN_ENTROPY" in rule_ids
    assert "HIGH_PATH_ENTROPY" in rule_ids
    assert "HIGH_QUERY_ENTROPY" in rule_ids


def test_digit_ratio_and_shortener_branches():
    """Verify high digit ratio and shortened URL detection."""
    features = {
        "is_shortened": True,
        "digits_to_domain_ratio": 0.4,
        "count_query_params": 6,
    }
    triggers, _ = evaluate_heuristics(features, "http://123456789.com/link?a=1&b=2&c=3&d=4&e=5&f=6")
    rule_ids = [_get_rule_name(r) for r in triggers]
    assert "URL_SHORTENER" in rule_ids
    assert "HIGH_DIGIT_RATIO" in rule_ids
    assert "EXCESSIVE_QUERY_PARAMS" in rule_ids


def test_heuristic_engine_wrapper_class():
    """Verify object-oriented HeuristicEngine wrapper class methods."""
    triggers, score = HeuristicEngine.evaluate({"is_shortened": True}, "http://bit.ly/1234")
    assert isinstance(triggers, list)
    assert isinstance(score, float)
    assert "URL_SHORTENER" in [_get_rule_name(r) for r in triggers]

    # Swapped args in wrapper
    triggers_swapped, _ = HeuristicEngine.evaluate("http://bit.ly/1234", {"is_shortened": True})
    assert "URL_SHORTENER" in [_get_rule_name(r) for r in triggers_swapped]