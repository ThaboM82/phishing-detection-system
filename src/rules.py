import json
import os
import re
from urllib.parse import urlparse

class HeuristicEngine:
    def __init__(self, config_path: str = None):
        if config_path is None:
            config_path = os.path.join(os.path.dirname(__file__), "..", "config", "rules.json")
        
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8-sig") as f:
                self.config = json.load(f)
        else:
            self.config = {
                "max_url_length": 75,
                "max_special_chars": 5,
                "max_subdomains": 3,
                "max_entropy": 4.5,
                "block_ip_hostnames": True,
                "flag_sensitive_keywords": True
            }

    def evaluate(self, url: str, features: dict, ml_prob: float) -> dict:
        fired_rules = []
        parsed = urlparse(url)

        # Rule 1: IP Address Hostname
        if self.config.get("block_ip_hostnames", True):
            ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
            if re.match(ip_pattern, parsed.netloc.split(":")[0]):
                fired_rules.append({"rule": "IP_HOST_BLOCKED", "reason": "Host uses an IP address directly."})

        # Rule 2: Excessive URL Length
        max_len = self.config.get("max_url_length", 75)
        if len(url) > max_len:
            fired_rules.append({"rule": "EXCESSIVE_URL_LENGTH", "reason": f"URL length ({len(url)}) exceeds limit ({max_len})."})

        # Rule 3: High Entropy
        max_entropy = self.config.get("max_entropy", 4.5)
        if features.get("url_entropy", 0) > max_entropy:
            fired_rules.append({"rule": "HIGH_ENTROPY_PATH", "reason": f"URL entropy ({features.get('url_entropy', 0):.2f}) exceeds threshold ({max_entropy})."})

        # Rule 4: Sensitive Keywords
        if self.config.get("flag_sensitive_keywords", True):
            keywords = ["login", "verify", "secure", "update", "account", "banking", "paypal", "signin"]
            found_kw = [kw for kw in keywords if kw in url.lower()]
            if found_kw:
                fired_rules.append({"rule": "SENSITIVE_KEYWORDS_FOUND", "reason": f"Found targeted keywords: {', '.join(found_kw)}"})

        # Determine verdict
        heuristic_count = len(fired_rules)
        if ml_prob >= 0.75 or any(r["rule"] == "IP_HOST_BLOCKED" for r in fired_rules):
            verdict = "BLOCKED"
            is_phishing = True
        elif ml_prob >= 0.40 or heuristic_count >= 1:
            verdict = "SUSPICIOUS"
            is_phishing = True
        else:
            verdict = "BENIGN"
            is_phishing = False

        return {
            "is_phishing": is_phishing,
            "verdict": verdict,
            "ml_probability": ml_prob,
            "fired_rules": fired_rules,
            "heuristic_flags_count": heuristic_count
        }
