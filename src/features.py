"""
src/features.py

Feature extraction engine for the phishing detection system.
Extracts structural, lexical, behavioral, and statistical features from URLs.
"""

import math
import re
from typing import Any, Dict, List
from urllib.parse import parse_qs, unquote, urlparse

from src.config import (
    DOMAIN_WHITELIST,
    HIGH_RISK_TLDS,
    SUSPICIOUS_KEYWORDS,
    TARGET_BRANDS,
    URL_SHORTENERS,
)

# Canonical 17-feature schema order expected by ML RandomForest model
MODEL_FEATURE_NAMES: List[str] = [
    "url_length",
    "domain_length",
    "dot_count",
    "hyphen_count",
    "at_count",
    "question_count",
    "equal_count",
    "slash_count",
    "digit_count",
    "is_ip_address",
    "is_shortened",
    "is_high_risk_tld",
    "suspicious_keywords",
    "subdomain_count",
    "has_https",
    "non_standard_port",
    "brand_spoofing_detected",
]

# Alias for feature schema reflection
FEATURE_NAMES: List[str] = MODEL_FEATURE_NAMES

# Pre-compile regex for IPv4 checking to avoid repetitive runtime compilation
IP_PATTERN: re.Pattern = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def is_punycode(domain: str) -> bool:
    """Checks if a domain contains Punycode ('xn--') or non-ASCII Unicode characters."""
    if not domain:
        return False

    if "xn--" in domain.lower():
        return True

    try:
        domain.encode("ascii")
        return False
    except (UnicodeEncodeError, UnicodeDecodeError):
        return True


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy to measure character randomness."""
    if not text:
        return 0.0
    entropy = 0.0
    text_len = len(text)
    for char in set(text):
        p_x = text.count(char) / text_len
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 4)


def get_registered_domain(netloc: str) -> str:
    """Extracts registered domain, stripping standard port, 'www.', and multi-part ccTLDs."""
    if not netloc:
        return ""

    # Strip port if present
    domain = netloc.split(":")[0].strip().lower()
    if domain.startswith("www."):
        domain = domain[4:]

    parts = [p for p in domain.split(".") if p]
    if not parts:
        return ""

    # Special handling for common multi-part ccTLDs (e.g., .co.za, .gov.za, .org.uk)
    if len(parts) > 2 and parts[-2] in {"co", "gov", "org", "ac", "net", "edu"}:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def check_typosquatting(domain: str) -> bool:
    """Detects visual brand character substitutions (e.g., paypa1, g00gle, c4pitec)."""
    if not domain:
        return False

    clean_domain = get_registered_domain(domain)

    if not clean_domain or clean_domain in DOMAIN_WHITELIST:
        return False

    normalized = (
        clean_domain.replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("4", "a")
        .replace("5", "s")
        .replace("@", "a")
    )
    for brand in TARGET_BRANDS:
        if brand in normalized and brand not in clean_domain:
            return True
    return False


def detect_homograph_attack(domain: str) -> bool:
    """Checks if a domain uses Punycode or non-ASCII/Cyrillic lookalike characters."""
    clean_domain = get_registered_domain(domain)
    return is_punycode(clean_domain)


def count_digits(text: str) -> int:
    """Counts the total number of numeric digits in a string."""
    if not text:
        return 0
    return sum(1 for c in text if c.isdigit())


def extract_features(url: str) -> Dict[str, Any]:
    """Extracts structural, lexical, behavioral, and statistical features from a URL."""
    if not url or not isinstance(url, str):
        url = ""

    url_clean = url.strip()
    formatted_url = (
        url_clean if "://" in url_clean else f"http://{url_clean}" if url_clean else ""
    )

    try:
        parsed = urlparse(formatted_url)
    except Exception:
        # Fallback for malformed URLs
        parsed = urlparse("http://invalid-url.local")

    raw_netloc = parsed.netloc or (parsed.path.split("/")[0] if parsed.path else "")
    domain = raw_netloc.split(":")[0].lower() if raw_netloc else ""
    registered_domain = get_registered_domain(domain)

    path = parsed.path or ""
    query = parsed.query or ""
    path_and_query = (path + "?" + query).lower() if query else path.lower()

    domain_parts = registered_domain.split(".") if registered_domain else []
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""

    # Calculate subdomains relative to registered domain
    full_parts = [p for p in domain.split(".") if p]
    reg_parts = [p for p in registered_domain.split(".") if p]
    subdomain_count = max(0, len(full_parts) - len(reg_parts))

    url_len = max(len(url_clean), 1)
    domain_len = max(len(domain), 1)

    # Basic Structural & Lexical Metrics
    num_digits_url = count_digits(url_clean)
    num_digits_domain = count_digits(domain)
    query_params = parse_qs(query)

    # Single-pass character counts to minimize redundant string scans
    dot_count = url_clean.count(".")
    hyphen_count = url_clean.count("-")
    at_count = url_clean.count("@")
    question_count = url_clean.count("?")
    equal_count = url_clean.count("=")
    slash_count = url_clean.count("/")
    percent_count = url_clean.count("%")

    # Context-aware keyword matching (avoid false flagging whitelisted domains)
    url_lower = url_clean.lower()
    if registered_domain in DOMAIN_WHITELIST:
        kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in path_and_query)
    else:
        kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # Detect IP Address using pre-compiled regex
    is_ip = 1 if IP_PATTERN.match(domain) else 0

    # Brand Spoofing Check
    is_whitelisted = registered_domain in DOMAIN_WHITELIST
    brand_spoofed = 0
    if not is_whitelisted and url_clean:
        brand_in_url = any(
            b in url_lower and b not in registered_domain for b in TARGET_BRANDS
        )
        if check_typosquatting(domain) or brand_in_url:
            brand_spoofed = 1

    # Port extraction with exception handling
    try:
        port_num = parsed.port
        has_non_standard_port = 1 if port_num and port_num not in (80, 443) else 0
    except ValueError:
        has_non_standard_port = 1

    # Hex / percent decoding check
    try:
        unquoted = unquote(url_clean)
        has_hex = 1 if percent_count > 0 or unquoted != url_clean else 0
    except Exception:
        has_hex = 1

    # Safe double slash redirect calculation based on scheme position
    scheme_end = formatted_url.find("://")
    search_start = scheme_end + 3 if scheme_end != -1 else 0
    double_slash_redirect = 1 if url_clean.find("//", search_start) != -1 else 0

    features: Dict[str, Any] = {
        # Core Length Metrics
        "url_length": len(url_clean),
        "domain_length": len(domain),
        "path_length": len(path),
        "query_length": len(query),
        # Character & Token Counts
        "count_dots": dot_count,
        "dot_count": dot_count,
        "count_hyphens": hyphen_count,
        "hyphen_count": hyphen_count,
        "count_at": at_count,
        "at_count": at_count,
        "count_queries": question_count,
        "question_count": question_count,
        "count_equal": equal_count,
        "equal_count": equal_count,
        "count_slash": slash_count,
        "slash_count": slash_count,
        "count_percent": percent_count,
        "percent_encoded_count": percent_count,
        "count_digits_url": num_digits_url,
        "digit_count": num_digits_url,
        "count_digits_domain": num_digits_domain,
        "count_subdomains": subdomain_count,
        "subdomain_count": subdomain_count,
        "count_query_params": len(query_params),
        # Ratios & Proportions
        "digits_to_url_ratio": round(num_digits_url / url_len, 4),
        "digits_to_domain_ratio": round(num_digits_domain / domain_len, 4),
        # Statistical Entropy Metrics
        "domain_entropy": calculate_entropy(domain),
        "path_entropy": calculate_entropy(path),
        "query_entropy": calculate_entropy(query),
        # Binary/Flag Features
        "has_ip": is_ip,
        "is_ip_address": is_ip,
        "has_https": 1 if url_lower.startswith("https://") else 0,
        "is_shortened": 1 if registered_domain in URL_SHORTENERS else 0,
        "has_prefix_suffix": 1 if "-" in domain else 0,
        "non_standard_port": has_non_standard_port,
        "suspicious_keywords": kw_count,
        "is_high_risk_tld": 1 if tld in HIGH_RISK_TLDS else 0,
        "has_hex_encoding": has_hex,
        "typosquatting_detected": 1 if check_typosquatting(domain) else 0,
        "brand_spoofing_detected": brand_spoofed,
        "homograph_attack_detected": 1 if detect_homograph_attack(domain) else 0,
        "double_slash_redirect": double_slash_redirect,
        "domain": domain,
        "registered_domain": registered_domain,
        "is_whitelisted": is_whitelisted,
    }

    return features


def get_model_feature_vector(features: Dict[str, Any]) -> List[float]:
    """Slices extracted feature dict into the exact ordered list needed by ML model."""
    return [float(features.get(name, 0.0)) for name in MODEL_FEATURE_NAMES]


class FeatureExtractor:
    """Object-oriented interface wrapper for feature extraction operations."""

    FEATURE_NAMES = FEATURE_NAMES
    MODEL_FEATURE_NAMES = MODEL_FEATURE_NAMES

    def __init__(self, feature_names: List[str] = None):
        self.feature_names = feature_names or MODEL_FEATURE_NAMES

    @staticmethod
    def extract_features(url: str) -> Dict[str, Any]:
        return extract_features(url)

    @staticmethod
    def extract(url: str) -> Dict[str, Any]:
        """Alias for extract_features."""
        return extract_features(url)

    @staticmethod
    def get_model_feature_vector(features: Dict[str, Any]) -> List[float]:
        return get_model_feature_vector(features)

    def to_vector(self, features: Dict[str, Any]) -> List[float]:
        """Maps extracted feature dictionary to ordered feature vector."""
        return [float(features.get(name, 0.0)) for name in self.feature_names]

    @staticmethod
    def is_punycode(domain: str) -> bool:
        return is_punycode(domain)

    @staticmethod
    def calculate_entropy(text: str) -> float:
        return calculate_entropy(text)

    @staticmethod
    def get_registered_domain(netloc: str) -> str:
        return get_registered_domain(netloc)

    @staticmethod
    def check_typosquatting(domain: str) -> bool:
        return check_typosquatting(domain)

    @staticmethod
    def detect_homograph_attack(domain: str) -> bool:
        return detect_homograph_attack(domain)