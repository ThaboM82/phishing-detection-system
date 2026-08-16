import re
from typing import Dict, Any, List, Optional

# Broad set of security, auth, financial, tech, and crypto keywords commonly targeted in phishing lures
SENSITIVE_KEYWORDS = {
    # Authentication & Action lures
    'login', 'signin', 'auth', 'verify', 'verification', 'update', 'account',
    'password', 'security', 'secure', 'credential', 'support', 'billing', '2fa',
    
    # Major Tech & Social Platforms
    'paypal', 'apple', 'google', 'microsoft', 'ebay', 'amazon', 'facebook',
    'instagram', 'meta', 'netflix', 'office365', 'outlook', 'dropbox', 'github',
    
    # Financial & Crypto Entities
    'bank', 'chase', 'wellsfargo', 'binance', 'coinbase', 'metamask', 'wallet', 'crypto'
}

class HeuristicEngine:
    """Class wrapper for heuristic engine evaluation with configurable thresholds."""
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    def evaluate(self, url: str, features: Dict[str, Any]) -> Dict[str, Any]:
        return evaluate_heuristics(url, features, config=self.config)


def evaluate_heuristics(
    url: str, 
    features: Dict[str, Any], 
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Evaluates rule-based heuristics against extracted URL features using dynamic configuration limits.
    """
    if config is None:
        config = {}

    # Extract dynamic threshold configurations with safe default fallbacks
    max_url_len = config.get("max_url_length", 75)
    max_spec_chars = config.get("max_special_chars", 10)
    max_subdomains = config.get("max_subdomains", 3)
    max_entropy = config.get("max_entropy", 4.5)
    block_ip_hostnames = config.get("block_ip_hostnames", True)
    flag_sensitive_keywords = config.get("flag_sensitive_keywords", True)

    fired_rules: List[str] = []
    url_lower = url.lower()

    # Rule 1: IP Address Used in Hostname
    if block_ip_hostnames and features.get('has_ip') == 1:
        fired_rules.append("IP_ADDRESS_USED")

    # Rule 2: Contains Sensitive Brand/Security Keywords
    if flag_sensitive_keywords:
        found_keywords = [kw for kw in SENSITIVE_KEYWORDS if kw in url_lower]
        if found_keywords or features.get('contains_sensitive_keyword') == 1:
            fired_rules.append("SENSITIVE_KEYWORDS_FOUND")

    # Rule 3: High Entropy (Obfuscated or Random Strings)
    if features.get('entropy', 0) > max_entropy:
        fired_rules.append("HIGH_ENTROPY_URL")

    # Rule 4: Excessive Subdomains
    if features.get('subdomain_count', 0) >= max_subdomains:
        fired_rules.append("EXCESSIVE_SUBDOMAINS")

    # Rule 5: Excessive URL Length
    if features.get('url_length', len(url)) > max_url_len:
        fired_rules.append("EXCESSIVE_URL_LENGTH")

    # Rule 6: High Special Character Density
    special_chars_count = features.get(
        'special_char_count', 
        len(re.findall(r'[@\-_=\?&\.%]', url))
    )
    if special_chars_count > max_spec_chars:
        fired_rules.append("EXCESSIVE_SPECIAL_CHARS")

    # Rule 7: Non-Standard Port Usage (e.g., http://example.com:8080)
    if re.search(r':(?!80|443)\d{2,5}', url):
        fired_rules.append("NON_STANDARD_PORT")

    return {
        'fired_rules': fired_rules,
        'flags_count': len(fired_rules)
    }