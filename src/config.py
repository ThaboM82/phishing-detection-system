import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs"

DATA_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Database Configuration
DB_NAME = "phishing_detector.db"
DB_PATH = os.getenv("DB_PATH", str(BASE_DIR / DB_NAME))
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DB_PATH}")

# Model Paths
MODEL_PATH = os.getenv("MODEL_PATH", str(MODELS_DIR / "phishing_rf_model.pkl"))
MODEL_DIR = MODELS_DIR

# API Settings
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 8000))
DEBUG_MODE = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")

# Hybrid Scoring & Thresholds
RISK_THRESHOLD_PHISHING = int(os.getenv("RISK_THRESHOLD_PHISHING", 50))
HEURISTIC_WEIGHT = float(os.getenv("HEURISTIC_WEIGHT", 0.15))
ML_WEIGHT = float(os.getenv("ML_WEIGHT", 1.0 - HEURISTIC_WEIGHT))
PHISHING_THRESHOLD = float(os.getenv("PHISHING_THRESHOLD", 0.5))

RISK_LEVELS = {
    "LOW": (0, 29),
    "MEDIUM": (30, 59),
    "HIGH": (60, 84),
    "CRITICAL": (85, 100),
}

# Heuristic Rule Bounds
MAX_URL_LENGTH_NORMAL = 75
MAX_SUBDOMAINS_NORMAL = 2
HIGH_ENTROPY_THRESHOLD = 4.2

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "auth", "authenticate", "verification",
    "verify", "validation", "update", "secure", "security", "account", "profile",
    "password", "credential", "reset", "recovery", "mfa", "2fa", "token",
    "banking", "wallet", "checkout", "billing", "payment", "invoice", "refund",
    "transfer", "crypto", "binance", "coinbase", "metamask",
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "instagram", "chase", "wellsfargo", "bankofamerica", "outlook", "office365",
    "standardbank", "capitec", "fnb", "absa", "nedbank",
    "sars", "discovery", "vodacom", "mtn", "tyme"
]

TARGET_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "capitec", "fnb", "standardbank", "absa", "nedbank", "discovery", "sars", "vodacom", "mtn"
]

BRAND_KEYWORDS = TARGET_BRANDS

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "gq", "ml", "cf", "tk", "ga", "fit", "surf",
    "icu", "buzz", "cn", "ru", "live", "club", "site", "online", "zip", "mov"
}
HIGH_RISK_TLDS = SUSPICIOUS_TLDS

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "tiny.cc", "s.id"
}

DOMAIN_WHITELIST = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "github.com",
    "wikipedia.org", "python.org", "paypal.com", "netflix.com", "www.google.com",
    "standardbank.co.za", "capitecbank.co.za", "fnb.co.za", "absa.co.za",
    "nedbank.co.za", "sars.gov.za", "discovery.co.za", "vodacom.co.za", "mtn.co.za", "tymebank.co.za"
}