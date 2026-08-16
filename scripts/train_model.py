import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, roc_auc_score

import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.features import extract_features

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "rf_phishing_v1.joblib")

def generate_synthetic_dataset(n_samples=1000):
    np.random.seed(42)
    urls, labels = [], []

    legit_domains = ["google.com", "github.com", "wikipedia.org", "amazon.com", "stackoverflow.com"]
    phish_domains = ["192.168.1.1/login-update", "paypal-security-update-verify.com/login.php", 
                     "secure-appleid-verify-account.net/login/auth", "free-giftcard-claim-now.xyz/win"]

    for _ in range(n_samples // 2):
        base = np.random.choice(legit_domains)
        path = "" if np.random.rand() > 0.5 else f"/page/{np.random.randint(100, 999)}"
        urls.append(f"https://{base}{path}")
        labels.append(0)

    for _ in range(n_samples // 2):
        base = np.random.choice(phish_domains)
        urls.append(f"http://{base}?id={np.random.randint(10000, 99999)}&user=test@domain.com")
        labels.append(1)

    return pd.DataFrame({"url": urls, "label": labels})

def train():
    print("--- Extracting Features ---")
    df = generate_synthetic_dataset(n_samples=1000)
    feature_list = [extract_features(u) for u in df['url']]
    X = pd.DataFrame(feature_list)
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("--- Training Random Forest Model ---")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    print("\n[Model Performance Metrics]")
    print(f"  • Accuracy:  {accuracy_score(y_test, y_pred) * 100:.2f}%")
    print(f"  • Precision: {precision_score(y_test, y_pred) * 100:.2f}%")
    print(f"  • Recall:    {recall_score(y_test, y_pred) * 100:.2f}%")
    print(f"  • ROC-AUC:   {roc_auc_score(y_test, y_proba):.4f}\n")

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"Saved trained model to {MODEL_PATH}")

if __name__ == "__main__":
    train()
