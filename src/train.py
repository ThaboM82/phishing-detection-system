import argparse
import os
import random
import sys
from typing import Dict, Tuple, Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from src.config import HIGH_RISK_TLDS, MODEL_PATH, TARGET_BRANDS, URL_SHORTENERS
from src.features import MODEL_FEATURE_NAMES, extract_features


def set_seed(seed: int = 42) -> None:
    """Sets random seeds across libraries for strict reproducibility."""
    random.seed(seed)
    np.random.seed(seed)


def generate_synthetic_dataset(
    samples: int = 2000, seed: int = 42
) -> Tuple[np.ndarray, np.ndarray]:
    """Generates a balanced dataset covering edge cases for phishing and legitimate URLs."""
    set_seed(seed)
    feature_names = MODEL_FEATURE_NAMES
    X, y = [], []

    benign_domains = [
        "google.com",
        "github.com",
        "wikipedia.org",
        "python.org",
        "microsoft.com",
        "amazon.com",
        "stackoverflow.com",
        "apple.com",
    ]

    phishing_keywords = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "banking",
        "signin",
        "confirm",
    ]
    phishing_hosts = [
        "login-verify-update",
        "secure-account-auth",
        "banking-check",
        "update-security-info",
    ]

    target_brands_list = list(TARGET_BRANDS) if isinstance(TARGET_BRANDS, (set, dict)) else TARGET_BRANDS
    url_shorteners_list = list(URL_SHORTENERS) if isinstance(URL_SHORTENERS, (set, dict)) else URL_SHORTENERS
    high_risk_tlds_list = list(HIGH_RISK_TLDS) if isinstance(HIGH_RISK_TLDS, (set, dict)) else HIGH_RISK_TLDS

    half_samples = samples // 2

    # 1. Generate Legitimate Samples
    for _ in range(half_samples):
        domain = random.choice(benign_domains)
        has_sub = random.random() < 0.2
        subdomain = "docs." if has_sub else ""
        path_length = random.randint(0, 3)
        path = "/".join([f"path{i}" for i in range(path_length)])
        query = f"?id={random.randint(100, 9999)}" if random.random() < 0.3 else ""

        url = f"https://{subdomain}{domain}/{path}{query}"
        features = extract_features(url)
        vector = [float(features.get(name, 0.0)) for name in feature_names]
        X.append(vector)
        y.append(0)

    # 2. Generate Phishing Samples
    for _ in range(half_samples):
        mode = random.choice(["typo", "ip", "shortener", "subdomain_flood", "tld"])

        if mode == "typo":
            brand = random.choice(target_brands_list)
            subst = brand.replace("o", "0").replace("l", "1").replace("e", "3")
            url = f"http://{subst}-{random.choice(phishing_keywords)}.com/auth/login"
        elif mode == "ip":
            ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"
            url = f"http://{ip}:{random.choice([8080, 80, 8443])}/login"
        elif mode == "shortener":
            shortener = random.choice(url_shorteners_list)
            url = f"http://{shortener}/{random.choice(phishing_hosts)}"
        elif mode == "subdomain_flood":
            url = f"http://account.verify.security.login.{random.choice(phishing_hosts)}.net/index.html"
        else:
            tld = random.choice(high_risk_tlds_list)
            url = f"http://{random.choice(phishing_hosts)}.{tld}/verify?token={random.randint(10000, 99999)}"

        features = extract_features(url)
        vector = [float(features.get(name, 0.0)) for name in feature_names]
        X.append(vector)
        y.append(1)

    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)


def load_or_generate_data(
    csv_path: str = "data/phishing_urls.csv",
    synthetic_samples: int = 2000,
) -> Tuple[np.ndarray, np.ndarray]:
    """Attempts to load a CSV dataset; falls back to synthetic generation if unavailable."""
    feature_names = MODEL_FEATURE_NAMES

    if os.path.exists(csv_path):
        print(f"📂 Loading real training data from '{csv_path}'...")
        try:
            df = pd.read_csv(csv_path)
            
            url_col = next((c for c in df.columns if c.lower() in ("url", "urls", "link")), None)
            label_col = next((c for c in df.columns if c.lower() in ("label", "is_phishing", "phishing", "target")), None)

            if url_col and label_col:
                X, y = [], []
                for _, row in df.iterrows():
                    feats = extract_features(str(row[url_col]))
                    vector = [float(feats.get(name, 0.0)) for name in feature_names]
                    X.append(vector)
                    y.append(int(row[label_col]))
                return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)
            else:
                print(f"⚠️ CSV missing target columns (URL: {url_col}, Label: {label_col}). Falling back.")
        except Exception as e:
            print(f"⚠️ Failed to load CSV data ({e}). Falling back to synthetic generation.")

    print(f"⚙️ Generating synthetic training dataset ({synthetic_samples} samples)...")
    return generate_synthetic_dataset(samples=synthetic_samples)


def train_and_save(
    data_path: str = "data/phishing_urls.csv",
    output_path: str = MODEL_PATH,
    synthetic_samples: int = 2000,
) -> Dict[str, Any]:
    """Core training logic. Trains model, saves to file, and returns evaluation metrics."""
    set_seed(42)
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    X, y = load_or_generate_data(csv_path=data_path, synthetic_samples=synthetic_samples)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"🏋️ Training Random Forest Model on {len(X_train)} samples...")

    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, y_prob)),
    }

    print("\n" + "=" * 50)
    print(" 📊 MODEL TRAINING & EVALUATION METRICS")
    print("=" * 50)
    print(f" Accuracy  : {metrics['accuracy'] * 100:.2f}%")
    print(f" Precision : {metrics['precision'] * 100:.2f}%")
    print(f" Recall    : {metrics['recall'] * 100:.2f}%")
    print(f" F1-Score  : {metrics['f1'] * 100:.2f}%")
    print(f" ROC-AUC   : {metrics['roc_auc']:.4f}")
    print("-" * 50)

    print("\n📋 Detailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    importances = clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]

    print("⭐ TOP 5 PREDICTIVE FEATURES:")
    for idx in sorted_idx[:5]:
        print(f"   • {MODEL_FEATURE_NAMES[idx]:<25}: {importances[idx]:.4f}")

    joblib.dump(clf, output_path)
    print(f"\n✅ Model successfully exported to: {output_path}\n")

    return metrics


def main(argv=None) -> int:
    """CLI entry point parsing command-line parameters."""
    parser = argparse.ArgumentParser(description="Train the phishing detection Random Forest model.")
    parser.add_argument("--data-path", type=str, default="data/phishing_urls.csv", help="Path to input dataset CSV")
    parser.add_argument("--output-path", type=str, default=MODEL_PATH, help="Path to output pickle file")
    parser.add_argument("--samples", type=int, default=2000, help="Number of synthetic samples if dataset missing")

    args = parser.parse_args(argv)

    try:
        train_and_save(
            data_path=args.data_path,
            output_path=args.output_path,
            synthetic_samples=args.samples,
        )
        return 0
    except Exception as e:
        print(f"❌ Training failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())