import re
import math
from typing import Dict, Any
from urllib.parse import urlparse

SENSITIVE_KEYWORDS = {
    "login", "signin", "account", "verify", "update", "banking",
    "secure", "webscr", "ebayisapi", "paypal", "password", "credential"
}

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work"}


def calculate_entropy(text: str) -> float:
    """Calculates Shannon Entropy of a given string."""
    if not text:
        return 0.0
    entropy = 0.0
    text_length = len(text)
    for x in set(text):
        p_x = float(text.count(x)) / text_length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 4)


def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Extracts numerical and boolean feature vectors from a raw URL.
    """
    if not url.startswith(("http://", "https://")):
        url_to_parse = "http://" + url
    else:
        url_to_parse = url

    parsed = urlparse(url_to_parse)
    domain = parsed.netloc.split(":")[0] if ":" in parsed.netloc else parsed.netloc
    
    # Clean domain subdomains
    domain_parts = domain.split(".")
    subdomain_count = max(0, len(domain_parts) - 2)

    url_len = len(url)
    domain_len = len(domain)
    digit_count_url = sum(c.isdigit() for c in url)
    digit_count_domain = sum(c.isdigit() for c in domain)
    letter_count_url = sum(c.isalpha() for c in url)
    letter_count_domain = sum(c.isalpha() for c in domain)

    has_ip = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) else 0
    contains_sensitive_kw = 1 if any(kw in url.lower() for kw in SENSITIVE_KEYWORDS) else 0

    return {
        "domain": domain,
        "url_length": url_len,
        "domain_length": domain_len,
        "subdomain_count": subdomain_count,
        "special_char_count": len(re.findall(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", url)),
        "entropy": calculate_entropy(url),
        "has_ip": has_ip,
        "contains_sensitive_keyword": contains_sensitive_kw,
        "is_https": 1 if url.startswith("https://") else 0,
        "has_at_symbol": 1 if "@" in url else 0,
        "has_double_slash": 1 if "//" in url[8:] else 0,
        "has_dash_in_domain": 1 if "-" in domain else 0,
        "tld_length": len(domain_parts[-1]) if len(domain_parts) > 1 else 0,
        "digit_count_url": digit_count_url,
        "digit_count_domain": digit_count_domain,
        "letter_count_url": letter_count_url,
        "letter_count_domain": letter_count_domain,
        "ratio_digits_url": round(digit_count_url / max(1, url_len), 4),
        "ratio_digits_domain": round(digit_count_domain / max(1, domain_len), 4),
        "query_length": len(parsed.query),
        "num_query_params": len(parsed.query.split("&")) if parsed.query else 0,
        "path_depth": len([p for p in parsed.path.split("/") if p]),
        "is_shortened_url": 1 if any(s in domain for s in ["bit.ly", "goo.gl", "tinyurl.com", "t.co"]) else 0,
        "non_standard_port": 1 if parsed.port and parsed.port not in (80, 443) else 0,
    }


class FeatureExtractor:
    """Class wrapper providing object-oriented feature extraction methods."""

    def extract_features(self, url: str) -> Dict[str, Any]:
        return extract_url_features(url)


# Class Aliases for legacy imports
URLFeatureExtractor = FeatureExtractor