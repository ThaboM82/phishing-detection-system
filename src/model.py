import os
import logging
from typing import List, Union, Dict, Any, Optional
import joblib
import pandas as pd
import numpy as np

logger = logging.getLogger("phishing_system.model")

# Default expected feature names to enforce DataFrame column alignment during inference
EXPECTED_FEATURES: List[str] = [
    "url_length",
    "domain_length",
    "subdomain_count",
    "special_char_count",
    "entropy",
    "has_ip",
    "contains_sensitive_keyword",
    "is_https",
    "has_at_symbol",
    "has_double_slash",
    "has_dash_in_domain",
    "tld_length",
    "digit_count_url",
    "digit_count_domain",
    "letter_count_url",
    "letter_count_domain",
    "ratio_digits_url",
    "ratio_digits_domain",
    "query_length",
    "num_query_params",
    "path_depth",
    "is_shortened_url",
    "non_standard_port",
]


class PhishingModel:
    """
    Wrapper class around the trained Machine Learning classifier (RandomForest / Sklearn).
    Handles thread-safe model loading, feature alignment, probabilistic inference,
    and graceful fallback scoring when an ML model artifact is missing.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model: Optional[Any] = None
        self.model_path: Optional[str] = model_path
        self.feature_names: List[str] = EXPECTED_FEATURES

        if model_path:
            self.load_model(model_path)

    def load_model(self, model_path: str) -> bool:
        """
        Loads the trained model artifact from disk via joblib.
        """
        if not os.path.exists(model_path):
            logger.warning(
                f"Model artifact not found at '{model_path}'. "
                "Engine will run in heuristic fallback mode."
            )
            self.model = None
            return False

        try:
            self.model = joblib.load(model_path)
            self.model_path = model_path
            
            # Inspect model for expected feature names if saved during fit
            if hasattr(self.model, "feature_names_in_"):
                self.feature_names = list(self.model.feature_names_in_)
            
            logger.info(f"Successfully loaded ML model artifact from '{model_path}'.")
            return True
        except Exception as e:
            logger.error(f"Failed to load model from '{model_path}': {e}")
            self.model = None
            return False

    def align_features(self, features_df: pd.DataFrame) -> pd.DataFrame:
        """
        Ensures the incoming DataFrame matches the exact column ordering and count
        expected by the trained estimator. Missing features are padded with zeros.
        """
        df = features_df.copy()

        # Fill missing features expected by the model
        for col in self.feature_names:
            if col not in df.columns:
                df[col] = 0

        # Reorder columns to strictly match model's fit signature
        return df[self.feature_names]

    def predict_proba(self, features: Union[pd.DataFrame, Dict[str, Any], List[Dict[str, Any]]]) -> np.ndarray:
        """
        Returns probability distribution array [[p_benign, p_phishing], ...].
        If no model is loaded, defaults to a safe fallback score based on entropy/keywords.
        """
        # 1. Normalize input to pandas DataFrame
        if isinstance(features, dict):
            df = pd.DataFrame([features])
        elif isinstance(features, list):
            df = pd.DataFrame(features)
        elif isinstance(features, pd.DataFrame):
            df = features
        else:
            raise ValueError(f"Unsupported features type: {type(features)}")

        # 2. Return model predictions if model is active
        if self.model is not None:
            try:
                aligned_df = self.align_features(df)
                return self.model.predict_proba(aligned_df)
            except Exception as exc:
                logger.error(f"Error during model predict_proba: {exc}. Falling back.")

        # 3. Fallback Heuristic Estimator (used if .pkl is missing or corrupt)
        probabilities = []
        for _, row in df.iterrows():
            prob_phishing = self._fallback_score(row)
            probabilities.append([1.0 - prob_phishing, prob_phishing])

        return np.array(probabilities)

    def predict_single_probability(self, features_dict: Dict[str, Any]) -> float:
        """
        Convenience method that returns the phishing probability (0.0 to 1.0)
        for a single extracted feature dictionary.
        """
        proba = self.predict_proba(features_dict)
        return float(proba[0][1])

    def _fallback_score(self, feature_row: pd.Series) -> float:
        """
        Computes a heuristic probability score (0.05 to 0.95) when the ML model
        artifact is unavailable.
        """
        score = 0.10  # Base benign probability
        
        if feature_row.get("has_ip", 0) == 1:
            score += 0.35
        if feature_row.get("contains_sensitive_keyword", 0) == 1:
            score += 0.25
        if feature_row.get("entropy", 0.0) > 4.5:
            score += 0.20
        if feature_row.get("subdomain_count", 0) >= 3:
            score += 0.10

        return min(round(score, 4), 0.95)


# Global instance initialized pointing to default models path
default_model_path = os.path.join("models", "phishing_rf_model.pkl")
model_instance = PhishingModel(model_path=default_model_path)