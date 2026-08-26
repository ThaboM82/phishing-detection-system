import logging
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse

from src.config import BRAND_KEYWORDS, SUSPICIOUS_KEYWORDS

logger = logging.getLogger(__name__)

# Module-level defaults for fallback execution
DEFAULT_WHITELIST: Set[str] = {
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "github.com",
    "fnb.co.za",
    "standardbank.co.za",
    "absa.co.za",
    "capitecbank.co.za",
    "nedbank.co.za",
    "sars.gov.za",
}

DEFAULT_TLD_RISK_SET: Set[str] = {
    "zip", "mov", "top", "xyz", "work", "click", "country", "gq", "tk", "ml", "cf"
}

# Common suspicious path patterns often targeted by credential harvesting attacks
PATH_KEYWORD_PATTERNS: Set[str] = {
    "/login",
    "/signin",
    "/sign-in",
    "/verify",
    "/verification",
    "/account",
    "/accounts",
    "/update",
    "/secure",
    "/banking",
    "/admin",
    "/webmail",
}

# Rule Severity Weights (allows granular risk scoring)
RULE_WEIGHTS: Dict[str, float] = {
    "BRAND_SPOOFING_ATTEMPT": 25.0,
    "IP_ADDRESS_USED": 25.0,
    "HOMOGRAPH_ATTACK": 20.0,
    "SUSPICIOUS_KEYWORD": 15.0,
    "HIGH_RISK_TLD": 15.0,
    "LONG_URL": 10.0,
    "EXCESSIVE_SUBDOMAINS": 10.0,
    "URL_SHORTENER": 10.0,
    "PREFIX_SUFFIX_HYPHEN": 10.0,
    "HIGH_DOMAIN_ENTROPY": 10.0,
    "HIGH_PATH_ENTROPY": 5.0,
    "HIGH_QUERY_ENTROPY": 5.0,
    "HEX_ENCODING": 5.0,
    "AT_SYMBOL_PRESENT": 15.0,
    "DOUBLE_SLASH_REDIRECT": 15.0,
    "HIGH_DIGIT_RATIO": 10.0,
    "EXCESSIVE_QUERY_PARAMS": 5.0,
    "INSECURE_HTTP": 5.0,
    "NON_STANDARD_PORT": 10.0,
}


def extract_registered_domain(url: str) -> str:
    """Extract clean registered domain or netloc from URL strings."""
    if not url:
        return ""

    parsed = urlparse(url if "://" in url else f"http://{url}")
    netloc = (parsed.netloc or parsed.path).split(":")[0].split("/")[0].lower()

    if netloc.startswith("www."):
        netloc = netloc[4:]

    return netloc


def is_whitelisted(domain: str, whitelist: Set[str]) -> bool:
    """Check if domain or its apex root is contained within the whitelist."""
    if not domain:
        return False
    return domain in whitelist or any(
        domain.endswith("." + white_domain) for white_domain in whitelist
    )


def evaluate_heuristics(
    features: Dict[str, Any], url: str
) -> Tuple[List[Dict[str, str]], float]:
    """Evaluates extracted features against static heuristic security rules."""
    # Handle swapped (url, features) arguments automatically
    if isinstance(features, str) and isinstance(url, (dict, type(None))):
        features, url = url or {}, features

    if not url or not isinstance(url, str) or not isinstance(features, dict):
        return [], 0.0

    domain = extract_registered_domain(url)

    # 0. Whitelist Guard (Short-circuit immediately for clean domains)
    domain_whitelist = set(features.get("domain_whitelist", DEFAULT_WHITELIST))
    if is_whitelisted(domain, domain_whitelist):
        return [], 0.0

    triggers: List[Dict[str, str]] = []
    triggered_rules_set: Set[str] = set()

    def add_trigger(rule_id: str, display_name: str) -> None:
        if rule_id not in triggered_rules_set:
            triggers.append({"rule": rule_id, "name": display_name})
            triggered_rules_set.add(rule_id)

    # 1. Host & Identity Anomalies
    if (
        features.get("has_ip", 0) == 1
        or features.get("is_ip", 0) == 1
        or features.get("is_ip_address", 0) == 1
    ):
        add_trigger("IP_ADDRESS_USED", "IP Address Used")

    if features.get("homograph_attack_detected"):
        add_trigger(
            "HOMOGRAPH_ATTACK",
            "Internationalized domain name (IDN/Punycode) detected",
        )

    if (
        features.get("typosquatting_detected")
        or features.get("brand_spoofing_detected")
    ):
        add_trigger("BRAND_SPOOFING_ATTEMPT", "Brand Spoofing Attempt")

    if features.get("is_shortened"):
        add_trigger("URL_SHORTENER", "URL shortening service detected")

    # Refined Hyphen Evaluation: Only trigger if hyphens target known brands or occur excessively
    all_brands = set(BRAND_KEYWORDS).union(
        {"capitec", "fnb", "standardbank", "absa", "sars", "nedbank", "paypal"}
    )
    url_lower = url.lower()
    has_hyphen_brand_target = "-" in domain and any(brand in domain for brand in all_brands)
    excessive_hyphens = domain.count("-") >= 2

    if features.get("has_prefix_suffix") and (has_hyphen_brand_target or excessive_hyphens):
        add_trigger("PREFIX_SUFFIX_HYPHEN", "Domain uses hyphens to simulate brands")

    subdomain_count = features.get(
        "count_subdomains", features.get("subdomain_count", 0)
    )
    if subdomain_count >= 3:
        add_trigger("EXCESSIVE_SUBDOMAINS", "Excessive subdomains detected")

    # High-Risk TLD verification
    tld = domain.split(".")[-1] if "." in domain else ""
    if features.get("is_high_risk_tld") or tld in DEFAULT_TLD_RISK_SET:
        add_trigger("HIGH_RISK_TLD", "Uses high-risk top level domain")

    # 2. Entropy & Obfuscation Metrics
    if features.get("domain_entropy", 0.0) > 4.2:
        add_trigger("HIGH_DOMAIN_ENTROPY", "High domain entropy")

    if features.get("path_entropy", 0.0) > 4.5:
        add_trigger("HIGH_PATH_ENTROPY", "High path entropy")

    if features.get("query_entropy", 0.0) > 4.8:
        add_trigger("HIGH_QUERY_ENTROPY", "High query string entropy")

    if features.get("has_hex_encoding") or features.get("percent_encoded_count", 0) > 2:
        add_trigger("HEX_ENCODING", "Contains hex/percent encoding")

    # 3. Structural, Length & Redirect Anomalies
    url_length = features.get("url_length", len(url))
    max_len = features.get("max_url_length_threshold", 75)
    if url_length > max_len:
        add_trigger("LONG_URL", "Long URL length")

    if (
        features.get("has_at_symbol", 0) == 1
        or features.get("count_at", features.get("at_count", 0)) > 0
    ):
        add_trigger("AT_SYMBOL_PRESENT", "At symbol present")

    if features.get("double_slash_redirect"):
        add_trigger("DOUBLE_SLASH_REDIRECT", "Double slash redirect")

    if features.get("digits_to_domain_ratio", 0.0) > 0.3:
        add_trigger("HIGH_DIGIT_RATIO", "High numeric digits in domain")

    if features.get("count_query_params", 0) >= 5:
        add_trigger("EXCESSIVE_QUERY_PARAMS", "Excessive query parameters")

    # 4. Network & Protocol Warnings
    if not features.get("has_https", True):
        add_trigger("INSECURE_HTTP", "Insecure HTTP connection")

    if features.get("non_standard_port"):
        add_trigger("NON_STANDARD_PORT", "Uses non-standard network port")

    # 5. Keyword & Brand Targeting Evaluation
    parsed_url = urlparse(url_lower if "://" in url_lower else f"http://{url_lower}")
    url_path = parsed_url.path or ""

    suspicious_kw_count = features.get("suspicious_keywords", 0)

    has_suspicious_match = False
    if isinstance(suspicious_kw_count, (int, float)) and suspicious_kw_count > 0:
        has_suspicious_match = True
    elif any(keyword in url_lower for keyword in SUSPICIOUS_KEYWORDS):
        has_suspicious_match = True
    elif any(pattern in url_path for pattern in PATH_KEYWORD_PATTERNS):
        has_suspicious_match = True

    if has_suspicious_match:
        add_trigger("SUSPICIOUS_KEYWORD", "Suspicious keyword present")

    if any(brand in url_lower for brand in all_brands):
        if not is_whitelisted(domain, domain_whitelist):
            add_trigger("BRAND_SPOOFING_ATTEMPT", "Brand Spoofing Attempt")

    # Calculate dynamic weighted score
    raw_score = sum(RULE_WEIGHTS.get(t["rule"], 10.0) for t in triggers)
    score = min(max(float(raw_score), 0.0), 100.0)

    return triggers, score


class HeuristicEngine:
    """Object-oriented interface wrapper for rule evaluation."""

    @staticmethod
    def evaluate(features: Any, url: Any = None) -> Tuple[List[Dict[str, str]], float]:
        if isinstance(features, str):
            features, url = url or {}, features
        return evaluate_heuristics(features or {}, url or "")