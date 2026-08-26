import asyncio
from concurrent.futures import ThreadPoolExecutor
import logging
import pickle
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import joblib

from src.config import (
    DOMAIN_WHITELIST,
    HEURISTIC_WEIGHT,
    ML_WEIGHT,
    MODEL_PATH,
    PHISHING_THRESHOLD,
    RISK_LEVELS,
)
from src.features import FEATURE_NAMES, FeatureExtractor
from src.heuristics import HeuristicEngine, evaluate_heuristics

logger = logging.getLogger(__name__)


class PhishingDetectionPipeline:
    """Core inference pipeline combining feature extraction, machine learning model
    predictions, and heuristic risk scoring to evaluate URL safety.
    """

    FEATURE_NAMES: List[str] = FEATURE_NAMES

    def __init__(
        self,
        model: Optional[Any] = None,
        scaler: Optional[Any] = None,
        feature_names: Optional[List[str]] = None,
        phishing_threshold: float = PHISHING_THRESHOLD,
        ml_weight: float = ML_WEIGHT,
        heuristic_weight: float = HEURISTIC_WEIGHT,
        model_path: Optional[Union[str, Path]] = None,
        executor: Optional[ThreadPoolExecutor] = None,
    ) -> None:
        self.model_path = Path(model_path or MODEL_PATH)
        self.scaler = scaler
        self.feature_names = feature_names or self.FEATURE_NAMES
        self.phishing_threshold = phishing_threshold
        self.ml_weight = ml_weight
        self.heuristic_weight = heuristic_weight
        self.extractor = FeatureExtractor()
        self.heuristic_engine = HeuristicEngine()
        self._executor = executor
        self.model = model if model is not None else self._load_model()

    def _load_model(self) -> Any:
        if not self.model_path.exists():
            logger.warning(
                "Model file not found at %s. Operating in baseline heuristic mode.",
                self.model_path,
            )
            return None

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                return joblib.load(self.model_path)
        except Exception as joblib_err:
            logger.warning(
                "Failed loading model via joblib (%s). Attempting pickle fallback...",
                joblib_err,
            )

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                with open(self.model_path, "rb") as f:
                    return pickle.load(f)
        except Exception as pickle_err:
            logger.error("Failed to load model via pickle: %s", pickle_err)
            return None

    def _determine_risk_level(self, risk_score: float, is_phishing: bool, ml_prob: float) -> str:
        score = max(0.0, min(100.0, float(risk_score)))

        if score >= 80.0 or (is_phishing and ml_prob >= 0.85):
            return "CRITICAL"
        if score >= 65.0 or (is_phishing and ml_prob >= 0.65):
            return "HIGH"
        if score >= 35.0 or is_phishing:
            return "MEDIUM"
        return "LOW"

    def _predict_ml_probability(self, features_dict: Dict[str, Any]) -> float:
        if self.model is None:
            return 0.0

        try:
            if hasattr(self.extractor, "to_vector") and callable(self.extractor.to_vector):
                vector = self.extractor.to_vector(features_dict)
            elif self.feature_names:
                vector = [float(features_dict.get(col, 0.0)) for col in self.feature_names]
            else:
                vector = [float(v) for v in features_dict.values() if isinstance(v, (int, float, bool))]

            X = [vector]

            if self.scaler is not None:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    X = self.scaler.transform(X)

            if hasattr(self.model, "n_features_in_"):
                expected_dim = self.model.n_features_in_
                if len(X[0]) != expected_dim:
                    logger.warning(
                        "Feature mismatch: expected %s, got %s. Defaulting ML score to 0.0.",
                        expected_dim,
                        len(X[0]),
                    )
                    return 0.0

            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(X)
                probs_row = probs[0]
                return float(probs_row[1]) if len(probs_row) > 1 else float(probs_row[0])

            if hasattr(self.model, "predict"):
                preds = self.model.predict(X)
                return float(preds[0])
        except Exception as e:
            logger.error("Error during ML model inference: %s", e, exc_info=True)

        return 0.0

    def _build_error_response(self, url: str, message: str, scan_timestamp: str) -> Dict[str, Any]:
        return {
            "url": url,
            "is_phishing": False,
            "confidence": 0.0,
            "confidence_score": 0.0,
            "phishing_probability": 0.0,
            "risk_score": 0.0,
            "model_score": 0.0,
            "risk_level": "LOW",
            "prediction": "LEGITIMATE",
            "ml_probability": 0.0,
            "heuristic_score": 0.0,
            "heuristics_triggered": [],
            "triggered_rules": [],
            "features": {},
            "status": "error",
            "scan_timestamp": scan_timestamp,
            "message": message,
        }

    def _parse_heuristics(self, heur_res: Any) -> tuple[float, List[str]]:
        if isinstance(heur_res, dict):
            triggers = heur_res.get("triggered_rules", heur_res.get("heuristics_triggered", []))
            raw_score = heur_res.get("score", heur_res.get("heuristic_score", 0.0))
            return float(raw_score), list(triggers)

        if isinstance(heur_res, (list, tuple)) and len(heur_res) >= 2:
            first, second = heur_res[0], heur_res[1]
            if isinstance(first, (int, float)):
                score, triggers = first, second
            elif isinstance(second, (int, float)):
                score, triggers = second, first
            else:
                return 0.0, []
            return float(score), list(triggers) if isinstance(triggers, (list, tuple)) else []

        if isinstance(heur_res, (int, float)):
            return float(heur_res), []

        return 0.0, []

    def analyze_url(self, url: str) -> Dict[str, Any]:
        scan_timestamp = datetime.now(timezone.utc).isoformat()

        if not url or not isinstance(url, str) or not url.strip():
            return self._build_error_response(
                url=url if isinstance(url, str) else "",
                message="Invalid or empty URL provided.",
                scan_timestamp=scan_timestamp,
            )

        url_clean = url.strip()

        try:
            if hasattr(self.extractor, "extract_features"):
                features = self.extractor.extract_features(url_clean)
            elif hasattr(self.extractor, "extract"):
                features = self.extractor.extract(url_clean)
            else:
                features = {}
        except Exception as e:
            logger.error("Feature extraction failed for %s: %s", url_clean, e, exc_info=True)
            features = {}

        if hasattr(self.heuristic_engine, "evaluate"):
            heur_res = self.heuristic_engine.evaluate(url_clean, features)
        else:
            heur_res = evaluate_heuristics(features, url_clean)

        heuristic_score, triggers = self._parse_heuristics(heur_res)
        ml_prob = self._predict_ml_probability(features)

        domain = str(features.get("domain", "")).lower()
        whitelist_hit = (
            features.get("is_whitelisted", False)
            or domain in DOMAIN_WHITELIST
            or any(domain.endswith("." + d) for d in DOMAIN_WHITELIST if d)
        )

        if whitelist_hit:
            final_risk_prob = 0.0
            final_risk_score = 0.0
            is_phishing = False
        else:
            heuristic_prob = heuristic_score / 100.0 if heuristic_score > 1.0 else heuristic_score
            final_risk_prob = heuristic_prob if self.model is None else (
                (ml_prob * self.ml_weight) + (heuristic_prob * self.heuristic_weight)
            )

            if len(triggers) == 0 and heuristic_score == 0.0:
                is_phishing = ml_prob >= 0.75
            else:
                is_phishing = (
                    final_risk_prob >= self.phishing_threshold
                    or ml_prob >= 0.75
                    or heuristic_score >= 50.0
                )

            raw_calculated_score = final_risk_prob * 100.0
            if is_phishing:
                final_risk_score = round(max(35.0, min(100.0, raw_calculated_score)), 2)
            else:
                final_risk_score = round(max(0.0, min(34.9, raw_calculated_score)), 2)

        risk_level = self._determine_risk_level(final_risk_score, is_phishing, ml_prob)

        return {
            "url": url_clean,
            "is_phishing": is_phishing,
            "confidence": round(ml_prob, 4),
            "confidence_score": round(ml_prob, 4),
            "phishing_probability": round(final_risk_prob, 4),
            "risk_score": final_risk_score,
            "model_score": round(ml_prob, 4),
            "risk_level": risk_level,
            "prediction": "PHISHING" if is_phishing else "LEGITIMATE",
            "ml_probability": round(ml_prob, 4),
            "heuristic_score": round(heuristic_score, 2),
            "heuristics_triggered": triggers,
            "triggered_rules": triggers,
            "features": features,
            "status": "success",
            "scan_timestamp": scan_timestamp,
        }

    def inspect_url(self, url: str) -> Dict[str, Any]:
        return self.analyze_url(url)

    def analyze_batch(self, urls: List[str]) -> List[Dict[str, Any]]:
        if not isinstance(urls, list):
            logger.error("analyze_batch expects a list of URLs, received: %s", type(urls))
            return []

        results = []
        for raw_url in urls:
            try:
                results.append(self.analyze_url(raw_url))
            except Exception as e:
                logger.error("Error processing URL in batch (%s): %s", raw_url, e, exc_info=True)
                results.append(
                    self._build_error_response(
                        url=str(raw_url) if raw_url is not None else "",
                        message=f"Execution error: {str(e)}",
                        scan_timestamp=datetime.now(timezone.utc).isoformat(),
                    )
                )
        return results

    def inspect_batch(self, urls: List[str]) -> List[Dict[str, Any]]:
        return self.analyze_batch(urls)

    async def analyze_url_async(self, url: str) -> Dict[str, Any]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self.analyze_url, url)

    async def analyze_batch_async(self, urls: List[str]) -> List[Dict[str, Any]]:
        if not isinstance(urls, list):
            logger.error("analyze_batch_async expects a list of URLs, received: %s", type(urls))
            return []

        tasks = [self.analyze_url_async(u) for u in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        formatted_results = []
        for idx, res in enumerate(results):
            if isinstance(res, Exception):
                raw_url = urls[idx] if idx < len(urls) else ""
                formatted_results.append(
                    self._build_error_response(
                        url=str(raw_url),
                        message=f"Async processing error: {str(res)}",
                        scan_timestamp=datetime.now(timezone.utc).isoformat(),
                    )
                )
            else:
                formatted_results.append(res)
        return formatted_results

    async def inspect_batch_async(self, urls: List[str]) -> List[Dict[str, Any]]:
        return await self.analyze_batch_async(urls)

    def get_health_status(self) -> Dict[str, Any]:
        return {
            "model_loaded": self.model is not None,
            "scaler_loaded": self.scaler is not None,
            "configured_features_count": len(self.feature_names),
            "phishing_threshold": self.phishing_threshold,
            "weights": {
                "ml_weight": self.ml_weight,
                "heuristic_weight": self.heuristic_weight,
            },
        }


PhishingDetectorPipeline = PhishingDetectionPipeline
_pipeline_singleton: Optional[PhishingDetectionPipeline] = None


def get_pipeline() -> PhishingDetectionPipeline:
    global _pipeline_singleton
    if _pipeline_singleton is None:
        _pipeline_singleton = PhishingDetectionPipeline()
    return _pipeline_singleton


def predict_url(
    url: str,
    model: Optional[Any] = None,
    scaler: Optional[Any] = None,
    feature_names: Optional[List[str]] = None,
) -> Dict[str, Any]:
    if model is None and scaler is None and feature_names is None:
        pipeline = get_pipeline()
    else:
        pipeline = PhishingDetectionPipeline(
            model=model, scaler=scaler, feature_names=feature_names
        )
    return pipeline.analyze_url(url)