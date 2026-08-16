import os
import re
import math
import joblib
import numpy as np
import pandas as pd
import logging
from urllib.parse import urlparse
from typing import Dict, Any, List

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score

# Setup Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("model_trainer")

# Output artifact paths
ARTIFACT_DIR = os.getenv("ARTIFACT_DIR", "models")
MODEL_PATH = os.path.join(ARTIFACT_DIR, "phishing_rf_model.pkl")

# Sensitive keywords commonly present in phishing URLs
SENSITIVE_KEYWORDS = [
    "login", "signin", "bank", "account", "update", "verify", "secure",
    "webscr", "ebayisapi", "paypal", "password", "credential", "admin",
    "wallet", "billing", "confirm", "security", "token"
]

IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


# --- Feature Extraction Engine ---

def calculate_entropy(text: str) -> float:
    """Calculates Shannon Entropy for a given string."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return -sum([p * math.log(p, 2) for p in prob])


def extract_features_from_url(url: str) -> Dict[str, Any]:
    """Extracts numerical features from a raw URL string for ML training/inference."""
    # Ensure scheme for proper parsing
    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    # Feature 1: URL Length
    url_length = len(url)

    # Feature 2: Count of special characters
    special_chars = set("@-_?=&./%+")
    num_special_chars = sum(1 for char in url if char in special_chars)

    # Feature 3: Number of subdomains
    domain_parts = hostname.split(".")
    num_subdomains = max(0, len(domain_parts) - 2) if len(domain_parts) > 2 else 0

    # Feature 4: Shannon Entropy
    entropy = calculate_entropy(url)

    # Feature 5: Has IP address in hostname
    has_ip = 1 if IP_REGEX.match(hostname) else 0

    # Feature 6: Sensitive keyword count
    url_lower = url.lower()
    sensitive_keywords_count = sum(1 for kw in SENSITIVE_KEYWORDS if kw in url_lower)

    return {
        "url_length": url_length,
        "num_special_chars": num_special_chars,
        "num_subdomains": num_subdomains,
        "entropy": entropy,
        "has_ip": has_ip,
        "sensitive_keywords": sensitive_keywords_count
    }


def extract_features_from_dataset(df: pd.DataFrame, url_col: str = "url") -> pd.DataFrame:
    """Extracts features for a DataFrame containing raw URLs."""
    logger.info(f"Extracting features from {len(df)} URLs in dataset...")
    feature_list: List[Dict[str, Any]] = [
        extract_features_from_url(str(u)) for u in df[url_col]
    ]
    features_df = pd.DataFrame(feature_list)
    if "label" in df.columns:
        features_df["label"] = df["label"].values
    return features_df


# --- Synthetic Dataset Generation ---

def generate_synthetic_data(num_samples: int = 2000) -> pd.DataFrame:
    """Generates synthetic dataset if no external CSV is present."""
    logger.info(f"Generating synthetic feature dataset ({num_samples} samples)...")
    np.random.seed(42)

    benign_len = np.random.normal(35, 10, num_samples // 2).clip(15, 80)
    phish_len = np.random.normal(85, 25, num_samples // 2).clip(20, 300)
    url_length = np.concatenate([benign_len, phish_len])

    benign_spec = np.random.poisson(2, num_samples // 2)
    phish_spec = np.random.poisson(8, num_samples // 2)
    num_special_chars = np.concatenate([benign_spec, phish_spec])

    benign_sub = np.random.choice([0, 1, 2], size=num_samples // 2, p=[0.7, 0.25, 0.05])
    phish_sub = np.random.choice([1, 2, 3, 4], size=num_samples // 2, p=[0.2, 0.4, 0.3, 0.1])
    num_subdomains = np.concatenate([benign_sub, phish_sub])

    benign_ent = np.random.normal(3.2, 0.4, num_samples // 2).clip(1.5, 4.5)
    phish_ent = np.random.normal(4.8, 0.6, num_samples // 2).clip(3.0, 7.5)
    entropy = np.concatenate([benign_ent, phish_ent])

    has_ip = np.concatenate([
        np.random.choice([0, 1], size=num_samples // 2, p=[0.98, 0.02]),
        np.random.choice([0, 1], size=num_samples // 2, p=[0.70, 0.30])
    ])

    sensitive_keywords = np.concatenate([
        np.random.choice([0, 1], size=num_samples // 2, p=[0.95, 0.05]),
        np.random.choice([0, 1, 2, 3], size=num_samples // 2, p=[0.3, 0.4, 0.2, 0.1])
    ])

    labels = np.concatenate([np.zeros(num_samples // 2), np.ones(num_samples // 2)])

    df = pd.DataFrame({
        "url_length": url_length,
        "num_special_chars": num_special_chars,
        "num_subdomains": num_subdomains,
        "entropy": entropy,
        "has_ip": has_ip,
        "sensitive_keywords": sensitive_keywords,
        "label": labels
    })
    return df.sample(frac=1, random_state=42).reset_index(drop=True)


# --- Model Training Pipeline ---

def train_and_save_model(data_path: str = None, url_col: str = "url", label_col: str = "label"):
    """Loads dataset (or synthetic), extracts features, trains RF model, and exports model artifact."""
    if data_path and os.path.exists(data_path):
        logger.info(f"Loading raw dataset from {data_path}...")
        raw_df = pd.read_csv(data_path)
        
        if url_col in raw_df.columns:
            df = extract_features_from_dataset(raw_df, url_col=url_col)
        else:
            # Assume dataset is already pre-extracted numerical features
            df = raw_df
    else:
        logger.info("No raw URL dataset provided or found. Using synthetic feature training set.")
        df = generate_synthetic_data()

    X = df.drop(columns=[label_col])
    y = df[label_col]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    logger.info("Training Random Forest Classifier...")
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        min_samples_split=5,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    # Evaluation
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    auc_score = roc_auc_score(y_test, y_proba)
    logger.info(f"Model ROC-AUC Score: {auc_score:.4f}")
    logger.info("\n" + classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    # Feature Importance logging
    feature_importances = dict(zip(X.columns, clf.feature_importances_))
    logger.info(f"Feature Importances: {feature_importances}")

    # Save Artifacts
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    logger.info(f"Model saved successfully to '{MODEL_PATH}'.")


if __name__ == "__main__":
    train_and_save_model()