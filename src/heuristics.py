import math
import re
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urlparse

# --- WHITELISTS & TARGET LISTS ---

# Legitimate parent domains that bypass heuristic flag assignment
DEFAULT_WHITELIST: Set[str] = {
    # Global Trusted Domains
    "google.com",
    "facebook.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "github.com",
    "paypal.com",
    "chase.com",
    "wellsfargo.com",
    "binance.com",
    "coinbase.com",
    "netflix.com",
    "dropbox.com",
    # South African Trusted Domains
    "standardbank.co.za",
    "fnb.co.za",
    "absa.co.za",
    "vodacom.co.za",
    "takealot.com",
}

# Targeted brands frequently mimicked in typosquatting and subdomains
SENSITIVE_BRANDS: Set[str] = {
    # Global Brands
    "paypal", "apple", "google", "microsoft", "ebay", "amazon", "facebook",
    "instagram", "meta", "netflix", "office365", "outlook", "dropbox", "github",
    "chase", "wellsfargo", "binance", "coinbase", "metamask", "bankofamerica",
    # South African Brands
    "standardbank", "fnb", "absa", "vodacom", "takealot",
}

# High-intent action/security words commonly used in phishing lures
SENSITIVE_ACTIONS: Set[str] = {
    "login", "signin", "auth", "verify", "verification", "update", "account",
    "password", "security", "secure", "credential", "support", "billing", "2fa",
    "wallet", "crypto", "recover", "suspension", "unusual-activity"
}

# High-risk top-level domains frequently associated with phishing domains
SUSPICIOUS_TLDS: Set[str] = {
    ".zip", ".mov", ".top", ".xyz", ".work", ".click", ".fit", ".monster", ".gq", ".cf"
}

# --- CONFIGURATION DEFAULTS ---

DEFAULT_CONFIG: Dict[str, Any] = {
    "max_url_length": 75,
    "max_special_chars": 10,
    "max_subdomains": 3,
    "max_entropy": 4.5,
    "block_ip_hostnames": True,
    "flag_sensitive_keywords": True,
    "flag_brand_spoofing": True,
    "flag_non_standard_ports": True,
    "flag_suspicious_tlds": True,
}


# --- HELPER FUNCTIONS ---

def calculate_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a given string."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return round(-sum(p * math.log2(p) for p in prob), 4)


def extract_domain(url: str) -> str:
    """Extracts netloc/domain from URL string."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.netloc.lower().split(":")[0]


# --- ENGINE WRAPPER ---

class HeuristicEngine:
    """Class wrapper for heuristic evaluation with configurable thresholds and dynamic updates."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config: Dict[str, Any] = config or {}

    def update_config(self, new_config: Dict[str, Any]) -> None:
        """Dynamically update threshold values at runtime."""
        self.config.update(new_config)

    def evaluate(
        self, 
        url: str, 
        features: Optional[Dict[str, Any]] = None, 
        feature_vector: Optional[Dict[str, Any]] = None, 
        config: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Evaluates heuristic rules against extracted features."""
        feats = features if features is not None else (feature_vector or {})
        active_config = {**self.config, **(config or {})}
        return evaluate_heuristics(url, feats, config=active_config)


# --- MAIN EVALUATION ROUTINE ---

def evaluate_heuristics(
    url: str,
    features: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Evaluates rule-based heuristic checks against extracted URL features.
    
    Returns:
        Dict containing fired rules, flags count, and optional override verdicts.
    """
    active_config = {**DEFAULT_CONFIG, **(config or {})}
    fired_rules: List[str] = []
    override_verdict: Optional[str] = None

    url_lower = url.lower()
    domain = features.get("domain") or extract_domain(url)

    # 1. Whitelist Check (Clean short-circuit for high-trust domains)
    if domain in DEFAULT_WHITELIST or domain.endswith(tuple(f".{d}" for d in DEFAULT_WHITELIST)):
        return {
            "fired_rules": [],
            "flags_count": 0,
            "heuristic_flags_count": 0,
            "override_verdict": None,
        }

    # 2. IP Hostname Check
    if active_config.get("block_ip_hostnames"):
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        has_ip = features.get("has_ip") == 1 or re.match(ip_pattern, domain)
        if has_ip:
            fired_rules.append("IP_ADDRESS_USED")

    # 3. Brand Spoofing Check
    if active_config.get("flag_brand_spoofing"):
        for brand in SENSITIVE_BRANDS:
            if brand in url_lower and not (domain.endswith(f"{brand}.com") or domain.endswith(f"{brand}.co.za")):
                fired_rules.append(f"BRAND_SPOOFING_{brand.upper()}")
                if not override_verdict:
                    override_verdict = "SUSPICIOUS"

    # 4. Sensitive Keyword Check
    if active_config.get("flag_sensitive_keywords"):
        found_actions = [act for act in SENSITIVE_ACTIONS if act in url_lower]
        if len(found_actions) >= 2 or features.get("contains_sensitive_keyword") == 1:
            fired_rules.append("MULTIPLE_SENSITIVE_KEYWORDS")
        elif len(found_actions) == 1:
            fired_rules.append("SENSITIVE_KEYWORD_PRESENT")

    # 5. Shannon Entropy Check
    entropy = features.get("entropy", calculate_entropy(url))
    if entropy > active_config["max_entropy"]:
        fired_rules.append("HIGH_URL_ENTROPY")

    # 6. Subdomain Depth
    subdomain_count = features.get("subdomain_count", len(domain.split(".")) - 2)
    if subdomain_count >= active_config["max_subdomains"]:
        fired_rules.append("EXCESSIVE_SUBDOMAINS")

    # 7. URL Length Threshold
    url_length = features.get("url_length", len(url))
    if url_length > active_config["max_url_length"]:
        fired_rules.append("EXCESSIVE_URL_LENGTH")

    # 8. Special Character Density
    special_chars_count = features.get(
        "special_char_count",
        len(re.findall(r"[@\-_=\?&\.%#]", url))
    )
    if special_chars_count > active_config["max_special_chars"]:
        fired_rules.append("EXCESSIVE_SPECIAL_CHARS")

    # 9. Non-Standard Port Check
    if active_config.get("flag_non_standard_ports") and re.search(r":(?!80|443)\d{2,5}", url):
        fired_rules.append("NON_STANDARD_PORT")

    # 10. High-Risk TLD Check
    if active_config.get("flag_suspicious_tlds"):
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            fired_rules.append("SUSPICIOUS_TLD_DETECTED")

    flags_count = len(fired_rules)

    return {
        "fired_rules": fired_rules,
        "flags_count": flags_count,
        "heuristic_flags_count": flags_count,
        "override_verdict": override_verdict,
    }