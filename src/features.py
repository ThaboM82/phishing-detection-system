import math
import re
from urllib.parse import urlparse

SENSITIVE_KEYWORDS = {
    'login', 'signin', 'bank', 'account', 'update', 'verify',
    'secure', 'paypal', 'apple', 'google', 'microsoft', 'ebay'
}

SPECIAL_CHARS = ['@', '-', '?', '=', '_', '~', '%', '!', '$', '&', '*', '+', ';', '#']

def extract_features(url: str) -> dict:
    """Extracts structural and lexical features from a URL string."""
    if not url.startswith(('http://', 'https://')):
        parsed_url = urlparse(f'http://{url}')
    else:
        parsed_url = urlparse(url)

    netloc = parsed_url.netloc or parsed_url.path.split('/')[0]
    path = parsed_url.path if parsed_url.netloc else '/'.join(parsed_url.path.split('/')[1:])
    full_url = url.lower()

    url_length = len(full_url)
    domain_length = len(netloc)
    path_length = len(path)

    char_counts = {f'count_{c}': full_url.count(c) for c in SPECIAL_CHARS}
    total_special_chars = sum(char_counts.values())

    has_ip = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', netloc.split(':')[0]) else 0
    subdomain_count = max(0, len(netloc.split('.')) - 2)
    has_https = 1 if parsed_url.scheme == 'https' else 0

    # Shannon Entropy of URL
    entropy = 0.0
    if url_length > 0:
        freqs = {}
        for char in full_url:
            freqs[char] = freqs.get(char, 0) + 1
        entropy = -sum((count / url_length) * math.log2(count / url_length) for count in freqs.values())

    contains_sensitive_keyword = 1 if any(kw in full_url for kw in SENSITIVE_KEYWORDS) else 0

    return {
        'url_length': url_length,
        'domain_length': domain_length,
        'path_length': path_length,
        'total_special_chars': total_special_chars,
        'has_ip': has_ip,
        'subdomain_count': subdomain_count,
        'has_https': has_https,
        'entropy': round(entropy, 4),
        'contains_sensitive_keyword': contains_sensitive_keyword,
        **char_counts
    }
