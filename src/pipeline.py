import os
import logging
import joblib
from typing import Dict, Any, List, Optional
import pandas as pd

from src.features import extract_features
from src.heuristics import evaluate_heuristics

logger = logging.getLogger("phishing_pipeline")


class HeuristicEngineWrapper:
    """Wrapper class enabling dynamic configuration updates at runtime."""
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    def update_config(self, new_config: Dict[str, Any]) -> None:
        """Dynamically update heuristic thresholds without restarting the service."""
        self.config.update(new_config)
        logger.info(f"Heuristic Engine configuration updated: {self.config}")

    def evaluate(self, url: str, features: Dict[str, Any]) -> Dict[str, Any]:
        return evaluate_heuristics(url, features, config=self.config)


class PhishingDetectorPipeline:
    """Core hybrid detection pipeline combining heuristic checks and ML inference."""
    def __init__(self, model_path: str = "models/phishing_rf_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.heuristic_engine = HeuristicEngineWrapper()
        self._load_model()

    def _load_model(self) -> None:
        """Loads serialized model weights from disk."""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                logger.info(f"ML Model successfully loaded from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load ML model artifact from {self.model_path}: {e}")
                self.model = None
        else:
            logger.warning(f"Model file not found at {self.model_path}. Running in heuristic-only mode.")

    def reload_model(self, new_path: Optional[str] = None) -> bool:
        """Hot-reload model weights at runtime without process downtime."""
        if new_path:
            self.model_path = new_path
        self._load_model()
        return self.model is not None

    def update_heuristic_config(self, new_config: Dict[str, Any]) -> None:
        """Delegate dynamic heuristic rule updates to the engine wrapper."""
        self.heuristic_engine.update_config(new_config)

    def _compute_verdict(
        self, url: str, features: Dict[str, Any], heuristic_result: Dict[str, Any], ml_prob: float
    ) -> Dict[str, Any]:
        """Unified verdict calculation engine for single and batch predictions."""
        fired_rules = heuristic_result.get("fired_rules", [])
        flags_count = len(fired_rules)

        # Hybrid Decision Matrix
        if flags_count >= 2 or ml_prob >= 0.75:
            verdict = "PHISHING"
            is_phishing = True
        elif flags_count == 1 or ml_prob >= 0.40:
            verdict = "SUSPICIOUS"
            is_phishing = True
        else:
            verdict = "LEGITIMATE"
            is_phishing = False

        return {
            "url": url,
            "verdict": verdict,
            "is_phishing": is_phishing,
            "ml_probability": round(ml_prob, 4),
            "heuristic_flags_count": flags_count,
            "fired_rules": fired_rules,
            "extracted_features": features,
        }

    def inspect_url(self, url: str) -> Dict[str, Any]:
        """Processes a single URL through feature extraction, heuristics, and ML prediction."""
        if not url or not isinstance(url, str):
            raise ValueError("URL must be a non-empty string.")

        # 1. Feature Extraction
        features = extract_features(url)

        # 2. Heuristic Evaluation
        heuristic_result = self.heuristic_engine.evaluate(url, features)

        # 3. Machine Learning Inference
        ml_prob = 0.0
        if self.model is not None:
            try:
                feature_df = pd.DataFrame([features])
                if hasattr(self.model, "feature_names_in_"):
                    feature_df = feature_df.reindex(columns=self.model.feature_names_in_, fill_value=0)

                ml_prob = float(self.model.predict_proba(feature_df)[0][1])
            except Exception as e:
                logger.error(f"Error evaluating ML model prediction for '{url}': {e}")

        # 4. Return Hybrid Verdict
        return self._compute_verdict(url, features, heuristic_result, ml_prob)

    def inspect_urls_batch(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Vectorized batch inspection for rapid multi-URL evaluations."""
        if not urls:
            return []

        # 1. Feature Extraction & Heuristics for all URLs
        extracted = [extract_features(u) for u in urls]
        heuristics = [self.heuristic_engine.evaluate(u, feat) for u, feat in zip(urls, extracted)]

        # 2. Vectorized ML Inference
        ml_probs = [0.0] * len(urls)
        if self.model is not None:
            try:
                feature_df = pd.DataFrame(extracted)
                if hasattr(self.model, "feature_names_in_"):
                    feature_df = feature_df.reindex(columns=self.model.feature_names_in_, fill_value=0)

                probabilities = self.model.predict_proba(feature_df)
                ml_probs = [float(p[1]) for p in probabilities]
            except Exception as e:
                logger.error(f"Error performing batch ML prediction: {e}")

        # 3. Assemble Results
        return [
            self._compute_verdict(url, feat, heur, ml_prob)
            for url, feat, heur, ml_prob in zip(urls, extracted, heuristics, ml_probs)
        ]