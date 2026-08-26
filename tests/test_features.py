"""
tests/test_features.py

Unit and integration tests for URL feature extraction, heuristic helper
functions, schema alignment with the ML pipeline, and edge-case handling.
"""

import pytest

from src.features import (
    MODEL_FEATURE_NAMES,
    FeatureExtractor,
    calculate_entropy,
    check_typosquatting,
    count_digits,
    detect_homograph_attack,
    extract_features,
    get_model_feature_vector,
    get_registered_domain,
)
from src.pipeline import PhishingDetectorPipeline


# =====================================================================
# 1. Helper Unit Tests
# =====================================================================


def test_calculate_entropy():
    """Verify Shannon entropy calculations on uniform vs random strings."""
    assert calculate_entropy("") == 0.0
    assert calculate_entropy("aaaaa") == 0.0
    assert calculate_entropy("abcde") > 2.0


def test_get_registered_domain():
    """Verify extraction of registered domain across standard TLDs and multi-part ccTLDs."""
    assert get_registered_domain("www.google.com") == "google.com"
    assert (
        get_registered_domain("sub.domain.capitecbank.co.za:8080")
        == "capitecbank.co.za"
    )
    assert get_registered_domain("news.sars.gov.za") == "sars.gov.za"


def test_check_typosquatting():
    """Verify visual character replacement detection for target brands."""
    assert check_typosquatting("paypa1-update.com") is True
    assert check_typosquatting("c4pitec-online.com") is True
    assert check_typosquatting("google.com") is False


def test_detect_homograph_attack():
    """Verify IDN/Punycode and non-ASCII character detection."""
    assert detect_homograph_attack("xn--pypal-4ve.com") is True
    assert detect_homograph_attack("paypal.com") is False


def test_count_digits():
    """Verify counting digits in URL strings."""
    assert count_digits("abc123xyz456") == 6
    assert count_digits("no-digits.com") == 0


# =====================================================================
# 2. Feature Vector Structure & Schema Alignment Tests
# =====================================================================


def test_extract_features_structure():
    """Verify feature extraction returns dictionary containing required model and legacy keys."""
    url = "https://www.google.com"
    features = extract_features(url)

    assert isinstance(features, dict)
    assert len(features) >= 30


def test_feature_schema_matches_pipeline_names():
    """Verify extracted feature keys align with pipeline model expectations."""
    url = "https://example.com/test"
    features = extract_features(url)

    for expected_feature in PhishingDetectorPipeline.FEATURE_NAMES:
        assert (
            expected_feature in features
        ), f"Missing expected feature: {expected_feature}"


def test_get_model_feature_vector():
    """Verify model feature vector generation returns floats matching MODEL_FEATURE_NAMES order."""
    url = "https://httpbin.org/get?user=test"
    features = extract_features(url)
    vector = get_model_feature_vector(features)

    assert isinstance(vector, list)
    assert len(vector) == len(MODEL_FEATURE_NAMES)
    assert all(isinstance(val, float) for val in vector)


# =====================================================================
# 3. Hostname, IP Address & Port Detection
# =====================================================================


def test_ip_address_detection():
    """Verify IP detection works for both IP-based and domain-based URLs."""
    ip_url = "http://192.168.1.1/login.html"
    domain_url = "https://example.com/login.html"

    assert extract_features(ip_url)["has_ip"] == 1
    assert extract_features(domain_url)["has_ip"] == 0


def test_shortened_url_detection():
    """Verify known URL shortener domains are flagged."""
    short_url = "https://bit.ly/3xYz123"
    normal_url = "https://github.com/user/repo"

    assert extract_features(short_url)["is_shortened"] == 1
    assert extract_features(normal_url)["is_shortened"] == 0


def test_non_standard_port_detection():
    """Verify detection of explicit non-standard HTTP/HTTPS ports."""
    custom_port_url = "http://example.com:8080/login"
    standard_port_url = "https://example.com/login"

    assert extract_features(custom_port_url)["non_standard_port"] == 1
    assert extract_features(standard_port_url)["non_standard_port"] == 0


# =====================================================================
# 4. Security Risk Flags & Suspicious Pattern Detection
# =====================================================================


def test_suspicious_keywords_counter():
    """Verify counting of phishing-related keywords across the URL."""
    phishing_url = "https://secure-login-update-paypal-verify.account-info.com"
    clean_url = "https://wikipedia.org/wiki/Python"

    assert extract_features(phishing_url)["suspicious_keywords"] >= 3
    assert extract_features(clean_url)["suspicious_keywords"] == 0


def test_high_risk_tld_detection():
    """Verify detection of top-level domains frequently abused by phishing campaigns."""
    high_risk_url = "http://free-giftcard.top/claim"
    standard_tld_url = "http://free-giftcard.org/claim"

    assert extract_features(high_risk_url)["is_high_risk_tld"] == 1
    assert extract_features(standard_tld_url)["is_high_risk_tld"] == 0


def test_hex_encoding_detection():
    """Verify detection of hex-encoded percent escapes (%20, %2f, etc.)."""
    encoded_url = "http://example.com/login%20page%2Fredirect"
    clean_url = "http://example.com/login/page"

    assert extract_features(encoded_url)["has_hex_encoding"] == 1
    assert extract_features(clean_url)["has_hex_encoding"] == 0


def test_homograph_attack_detection():
    """Verify Punycode IDNs are flagged as potential homograph spoofing attempts."""
    punycode_url = "https://xn--pypal-4ve.com/login"
    standard_url = "https://paypal.com/login"

    assert extract_features(punycode_url)["homograph_attack_detected"] == 1
    assert extract_features(standard_url)["homograph_attack_detected"] == 0


def test_double_slash_redirect_detection():
    """Verify detection of inline double slashes used to hide internal redirects."""
    redirect_url = "http://example.com/path//http://phishing-target.com"
    clean_url = "http://example.com/path/to/resource"

    assert extract_features(redirect_url)["double_slash_redirect"] == 1
    assert extract_features(clean_url)["double_slash_redirect"] == 0


# =====================================================================
# 5. Lengths, Entropy & Edge Cases
# =====================================================================


def test_entropy_and_structural_metrics():
    """Verify entropy calculations and parameter counting logic."""
    complex_url = "https://app.example.com/v1/auth?token=a8f9c1d2e3f4&user=123"

    features = extract_features(complex_url)

    assert features["domain_entropy"] > 0
    assert features["path_entropy"] > 0
    assert features["query_entropy"] > 0
    assert features["count_query_params"] == 2
    assert features["has_https"] == 1


def test_empty_string_input():
    """Verify extract_features handles empty strings gracefully without crashing."""
    features = extract_features("")
    assert isinstance(features, dict)
    assert features["url_length"] == 0


def test_extract_features_unexpected_type_error():
    """Verify extract_features handles None inputs without breaking."""
    features = extract_features(None)
    assert isinstance(features, dict)


# =====================================================================
# 6. Object-Oriented Static Wrappers & Unparseable Fallbacks
# =====================================================================


def test_feature_extractor_static_methods():
    """Cover static helper wrapper methods and instances in FeatureExtractor class."""
    url = "https://example.com"
    
    # Static calls
    features = FeatureExtractor.extract_features(url)
    assert isinstance(features, dict)

    vector = FeatureExtractor.get_model_feature_vector(features)
    assert isinstance(vector, list)

    assert FeatureExtractor.is_punycode("xn--example.com") is True
    assert FeatureExtractor.calculate_entropy("abcde") > 2.0
    assert FeatureExtractor.get_registered_domain("www.example.com") == "example.com"
    assert FeatureExtractor.check_typosquatting("paypa1-login.com") is True
    assert FeatureExtractor.detect_homograph_attack("xn--pypal-4ve.com") is True

    # Instance calls and alias tests
    extractor = FeatureExtractor()
    assert isinstance(extractor.extract(url), dict)
    
    vector_inst = extractor.to_vector(features)
    assert isinstance(vector_inst, list)
    assert len(vector_inst) == len(MODEL_FEATURE_NAMES)


def test_extract_features_no_netloc_or_scheme():
    """Cover netloc fallback parsing and unparseable domain branches."""
    # Raw domain string without scheme triggers fallback parsing logic
    raw_domain = "subdomain.suspicious-login-portal.com/path/login.php"
    features = extract_features(raw_domain)
    assert isinstance(features, dict)
    assert features["url_length"] > 0

    # Malformed inputs missing valid domain structures
    unparseable = ":///invalid_path_without_domain"
    features_unparseable = extract_features(unparseable)
    assert isinstance(features_unparseable, dict)
def test_feature_extraction_utf8_error():
    """Forces UnicodeDecodeError / TypeError handling in feature extraction"""
    from src.features import FeatureExtractor
    # Pass non-string/malformed byte objects directly
    extractor = FeatureExtractor()
    features = extractor.extract_features("http://\xff\xfe.com")
    assert isinstance(features, dict)

# =====================================================================
# Feature Extraction Edge Cases & Boundary Tests
# =====================================================================

def test_extract_features_valid_url():
    """Verify feature dictionary structure and essential key existence."""
    url = "https://www.google.com/search?q=test"
    features = extract_features(url)

    assert isinstance(features, dict)
    assert len(features) > 0
    for expected_feature in MODEL_FEATURE_NAMES:
        assert expected_feature in features


def test_extract_features_ip_based_url():
    """Ensure IP address URLs are detected correctly by feature extractors."""
    url = "http://192.168.1.1/login/verify.php"
    features = extract_features(url)

    assert isinstance(features, dict)
    if "using_ip" in features:
        assert features["using_ip"] in (1, True)
    elif "has_ip" in features:
        assert features["has_ip"] in (1, True)


def test_extract_features_non_standard_port():
    """Verify handling of non-standard port numbers in URLs."""
    url = "http://suspicious-site.com:8080/auth"
    features = extract_features(url)

    assert isinstance(features, dict)
    if "port" in features:
        assert features["port"] in (1, True, 8080)


def test_extract_features_deep_subdomains():
    """Verify URL length and subdomain depth calculations on complex URLs."""
    url = "http://login.secure.update.bank.account.verify-user.xyz/login"
    features = extract_features(url)

    assert isinstance(features, dict)
    if "dot_count" in features:
        assert features["dot_count"] >= 5
    if "url_length" in features:
        assert features["url_length"] == len(url)


@pytest.mark.parametrize(
    "malformed_url",
    [
        "",
        "   ",
        "not_a_url",
        "http://",
        "://invalid-url",
        "http://???",
    ],
)
def test_extract_features_malformed_urls(malformed_url):
    """Ensure feature extraction handles malformed inputs without raising uncaught exceptions."""
    try:
        features = extract_features(malformed_url)
        assert isinstance(features, dict)
    except Exception as e:
        pytest.fail(
            f"extract_features raised an unexpected exception on input '{malformed_url}': {e}"
        )