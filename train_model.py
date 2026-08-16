import math
import os
import re
from urllib.parse import urlparse

import joblib
import mlflow
import mlflow.sklearn
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

# Import centralized feature extractor if available in project src
try:
    from src.features import extract_url_features
except ImportError:
    try:
        from src.pipeline import extract_url_features
    except ImportError:
        extract_url_features = None

# Set MLflow experiment name
mlflow.set_experiment("Phishing_Detection_System")


# --- 1. Enhanced 23-Feature Extraction Engine ---
def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon Entropy of a string to detect obfuscation/randomness."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(text)]
    return -sum(p * math.log2(p) for p in prob)


def fallback_extract_23_features(url: str) -> list:
    """
    Extract 23 lexical, structural, and statistical features to match the
    backend production pipeline schema:
    
    1. url_length          13. has_ip (binary)
    2. domain_length       14. keyword_match_count
    3. path_length         15. is_https (binary)
    4. entropy             16. tld_length
    5. dot_count           17. hyphen_in_domain (binary)
    6. hyphen_count        18. double_slash_redirect (binary)
    7. at_count            19. prefix_suffix (binary)
    8. question_count      20. digits_in_domain
    9. equals_count        21. path_depth
    10. slash_count        22. port_in_url (binary)
    11. digit_count        23. hex_character_count
    12. subdomain_count
    """
    url_str = str(url).strip()
    parsed = urlparse(url_str if url_str.startswith(("http://", "https://")) else f"http://{url_str}")
    
    netloc = parsed.netloc or parsed.path.split("/")[0]
    domain_host = netloc.split(":")[0]
    path = parsed.path if parsed.netloc else "/".join(parsed.path.split("/")[1:])

    # 1-4. Base Metrics
    url_length = len(url_str)
    domain_length = len(netloc)
    path_length = len(path)
    entropy = calculate_shannon_entropy(url_str)

    # 5-11. Delimiters and Special Characters
    dot_count = url_str.count(".")
    hyphen_count = url_str.count("-")
    at_count = url_str.count("@")
    question_count = url_str.count("?")
    equals_count = url_str.count("=")
    slash_count = url_str.count("/")
    digit_count = sum(c.isdigit() for c in url_str)

    # 12. Subdomain Structure
    subdomain_count = max(0, domain_host.count(".") - 1) if domain_host else 0
    
    # 13. Raw IP Host Indicator
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    has_ip = 1 if re.match(ip_pattern, domain_host) else 0

    # 14. Suspicious Keyword Density
    suspicious_keywords = ["login", "banking", "verify", "update", "paypal", "secure", "account", "webscr", "admin", "confirm"]
    url_lower = url_str.lower()
    keyword_match_count = sum(1 for kw in suspicious_keywords if kw in url_lower)

    # 15-23. Additional Structural Features for 23-Feature Vector
    is_https = 1 if url_lower.startswith("https://") else 0
    
    tld = domain_host.split(".")[-1] if "." in domain_host else ""
    tld_length = len(tld)
    
    hyphen_in_domain = 1 if "-" in domain_host else 0
    double_slash_redirect = 1 if url_str.find("//", 7) != -1 else 0
    prefix_suffix = 1 if "-" in domain_host else 0
    digits_in_domain = sum(c.isdigit() for c in domain_host)
    path_depth = len([p for p in path.split("/") if p])
    port_in_url = 1 if ":" in netloc and not netloc.endswith(":80") and not netloc.endswith(":443") else 0
    hex_character_count = len(re.findall(r"%[0-9a-fA-F]{2}", url_str))

    return [
        url_length, domain_length, path_length, entropy,
        dot_count, hyphen_count, at_count, question_count,
        equals_count, slash_count, digit_count, subdomain_count,
        has_ip, keyword_match_count, is_https, tld_length,
        hyphen_in_domain, double_slash_redirect, prefix_suffix,
        digits_in_domain, path_depth, port_in_url, hex_character_count
    ]


def get_feature_vector(url: str) -> list:
    """Uses src feature extractor if present, otherwise falls back to local 23-feature vector."""
    if extract_url_features is not None:
        features = extract_url_features(url)
        return list(features.values()) if isinstance(features, dict) else features
    return fallback_extract_23_features(url)


# --- 2. Training Pipeline ---
def train_and_log():
    data_path = os.path.join("data", "phishing_urls.csv")
    model_dir = "models"
    os.makedirs(model_dir, exist_ok=True)

    if not os.path.exists(data_path):
        print(f"Data file not found at '{data_path}'. Generating synthetic dataset for feature validation...")
        df = pd.DataFrame(
            {
                "url": [
                    "http://login-verification-secure-account.com/login.php",
                    "https://www.google.com",
                    "http://192.168.1.1/paypal.com/verify/index.html",
                    "https://github.com/Thabo/phishing-detection-system",
                    "http://secure-update-banking-portal.net/auth?id=99281",
                    "https://en.wikipedia.org/wiki/Phishing",
                ]
                * 25,
                "label": [1, 0, 1, 0, 1, 0] * 25,  # 1 = Phishing, 0 = Legitimate
            }
        )
    else:
        df = pd.read_csv(data_path)

    # Extract 23-element Feature Vectors
    X = np.array([get_feature_vector(u) for u in df["url"]])
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    with mlflow.start_run():
        n_estimators = 100
        max_depth = 15
        random_state = 42

        # Log Parameters
        mlflow.log_param("n_estimators", n_estimators)
        mlflow.log_param("max_depth", max_depth)
        mlflow.log_param("feature_count", X.shape[1])
        mlflow.log_param("model_type", "RandomForestClassifier")

        # Train Random Forest Classifier
        clf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            class_weight="balanced",
        )
        clf.fit(X_train, y_train)

        # Evaluate Metrics
        y_pred = clf.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)

        mlflow.log_metric("accuracy", acc)
        mlflow.log_metric("precision", prec)
        mlflow.log_metric("recall", rec)
        mlflow.log_metric("f1_score", f1)

        # Log Model using non-deprecated MLflow parameter 'name'
        mlflow.sklearn.log_model(clf, name="phishing_rf_model")

        # Persist local pickle artifact
        model_path = os.path.join(model_dir, "phishing_rf_model.pkl")
        joblib.dump(clf, model_path)

        print("\n--- Training Complete ---")
        print(f"Extracted Features : {X.shape[1]} vector elements")
        print(f"Accuracy           : {acc:.4f}")
        print(f"F1 Score           : {f1:.4f}")
        print(f"Saved local model to: {model_path}")


if __name__ == "__main__":
    train_and_log()