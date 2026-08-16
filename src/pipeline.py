import time
import logging
from typing import Dict, Any, List, Optional, Union
import pandas as pd

from src.features import FeatureExtractor
from src.heuristics import HeuristicEngine, DEFAULT_CONFIG
from src.model import model_instance, PhishingModel

logger = logging.getLogger("phishing_system.pipeline")

# Define exact feature order matching training schema
FEATURE_NAMES: List[str] = [
    "url_length",
    "entropy",
    "has_ip",
    "subdomain_count",
    "special_char_count",
    "contains_sensitive_keyword"
]


class PhishingPipeline:
    """
    Core hybrid engine orchestrating URL Feature Extraction, Rule-Based Heuristics,
    and Machine Learning Inference for real-time phishing detection.
    """

    def __init__(self, model_path: Optional[str] = None):
        """
        Initializes sub-engines. Uses global `model_instance` by default unless
        a custom model path is provided.
        """
        self.extractor = FeatureExtractor()
        self.heuristic_engine = HeuristicEngine()
        self.model = PhishingModel(model_path) if model_path else model_instance
        self.feature_names = FEATURE_NAMES
        logger.info("PhishingPipeline successfully initialized.")

    def update_heuristic_config(self, config: Dict[str, Any]) -> None:
        """
        Updates the internal heuristic configuration parameters dynamically.
        """
        if hasattr(self.heuristic_engine, "update_config"):
            self.heuristic_engine.update_config(config)
        elif hasattr(self.heuristic_engine, "config"):
            self.heuristic_engine.config.update(config)
        else:
            logger.warning("Heuristic engine does not support dynamic config updates.")
        logger.info("Updated heuristic configuration on pipeline instance.")

    def inspect_url(
        self, 
        url: str, 
        config: Optional[Dict[str, Any]] = None,
        include_features: bool = True
    ) -> Dict[str, Any]:
        """
        Evaluates a single URL across feature extraction, heuristics, and ML model.

        :param url: Target URL string to analyze.
        :param config: Dynamic configuration dictionary overriding default heuristic rules.
        :param include_features: Whether to include the full feature vector in the output dictionary.
        :return: Dict containing verdict, risk score, ML probability, and rule flags.
        """
        if not url or not isinstance(url, str) or not url.strip():
            raise ValueError("URL must be a non-empty string.")

        start_time = time.perf_counter()

        # 1. Feature Extraction
        t0 = time.perf_counter()
        feature_vector = self.extractor.extract_features(url)
        extraction_ms = round((time.perf_counter() - t0) * 1000, 2)

        # 2. Heuristic Rules Evaluation
        t1 = time.perf_counter()
        heuristic_res = self.heuristic_engine.evaluate(url, feature_vector, config=config)
        heuristics_ms = round((time.perf_counter() - t1) * 1000, 2)

        # 3. Machine Learning Inference with Safe Error Handling
        t2 = time.perf_counter()
        ml_proba = 0.5  # Fallback neutral score
        try:
            # Construct DataFrame with matching feature columns to prevent UserWarning
            df_single = pd.DataFrame([feature_vector])
            # Align columns if present, otherwise pass available features
            cols = [c for c in self.feature_names if c in df_single.columns]
            if cols:
                df_single = df_single[cols]
                
            ml_proba = float(self.model.predict_proba(df_single)[0][1])
        except Exception as err:
            logger.error(f"Error evaluating ML model prediction for '{url}': {err}")
            # Fallback directly to underlying method if DataFrame formatting fails
            try:
                ml_proba = float(self.model.predict_single_probability(feature_vector))
            except Exception:
                pass

        ml_inference_ms = round((time.perf_counter() - t2) * 1000, 2)

        # 4. Hybrid Decision Matrix Calculation
        flags_count = heuristic_res.get("flags_count", 0)
        fired_rules = heuristic_res.get("fired_rules", [])
        override_verdict = heuristic_res.get("override_verdict")

        # Heuristic weight scales with flag count up to a maximum contribution of 0.45
        heuristic_weight = min(flags_count * 0.15, 0.45)
        risk_score = round(min((ml_proba * 0.55) + heuristic_weight, 1.0), 4)

        # Verdict Resolution logic (Supports PHISHING along with SUSPICIOUS and BLOCKED)
        if override_verdict:
            verdict = override_verdict
            is_phishing = verdict in ["SUSPICIOUS", "BLOCKED", "PHISHING"]
        elif risk_score >= 0.70 or flags_count >= 3:
            verdict = "BLOCKED"
            is_phishing = True
        elif risk_score >= 0.40 or flags_count >= 1:
            verdict = "SUSPICIOUS"
            is_phishing = True
        else:
            verdict = "BENIGN"
            is_phishing = False

        total_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Build response schema
        result = {
            "url": url,
            "domain": feature_vector.get("domain", ""),
            "verdict": verdict,
            "is_phishing": is_phishing,
            "risk_score": risk_score,
            "ml_probability": round(ml_proba, 4),
            "flags_count": flags_count,
            "heuristic_flags_count": flags_count,  # Legacy alias for test backward-compatibility
            "override_verdict": override_verdict,
            "fired_rules": fired_rules,
            "execution_time_ms": total_ms,
            "timing_breakdown": {
                "feature_extraction_ms": extraction_ms,
                "heuristics_ms": heuristics_ms,
                "ml_inference_ms": ml_inference_ms,
            }
        }

        if include_features:
            result["feature_vector"] = feature_vector

        return result

    # Aliases for API & Test Fixtures calling evaluate_url/predict directly
    evaluate_url = inspect_url
    predict = inspect_url

    def inspect_batch(
        self, 
        urls: List[str], 
        config: Optional[Dict[str, Any]] = None,
        vectorized: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Evaluates a batch of URLs. Supports vectorized ML evaluation for improved throughput.

        :param urls: List of URL strings.
        :param config: Dynamic configuration dictionary overriding default heuristic rules.
        :param vectorized: If True, batches ML inference through a single DataFrame call.
        :return: List of inspection result dictionaries.
        """
        if not urls:
            return []

        if not vectorized:
            return [self.inspect_url(u, config=config) for u in urls]

        start_time = time.perf_counter()

        # Step A: Extract features and run heuristics across all URLs
        features_list = []
        heuristic_results = []
        
        for u in urls:
            f_vec = self.extractor.extract_features(u)
            h_res = self.heuristic_engine.evaluate(u, f_vec, config=config)
            features_list.append(f_vec)
            heuristic_results.append(h_res)

        # Step B: Batch ML prediction via Pandas DataFrame with column selection
        try:
            df_features = pd.DataFrame(features_list)
            cols = [c for c in self.feature_names if c in df_features.columns]
            if cols:
                df_features = df_features[cols]

            ml_probas = self.model.predict_proba(df_features)
        except Exception as err:
            logger.error(f"Error during batch ML prediction: {err}")
            ml_probas = [[0.5, 0.5] for _ in urls]

        # Step C: Synthesize final decisions
        results = []
        for idx, u in enumerate(urls):
            f_vec = features_list[idx]
            h_res = heuristic_results[idx]
            ml_proba = float(ml_probas[idx][1])

            flags_count = h_res.get("flags_count", 0)
            fired_rules = h_res.get("fired_rules", [])
            override_verdict = h_res.get("override_verdict")

            heuristic_weight = min(flags_count * 0.15, 0.45)
            risk_score = round(min((ml_proba * 0.55) + heuristic_weight, 1.0), 4)

            if override_verdict:
                verdict = override_verdict
                is_phishing = verdict in ["SUSPICIOUS", "BLOCKED", "PHISHING"]
            elif risk_score >= 0.70 or flags_count >= 3:
                verdict = "BLOCKED"
                is_phishing = True
            elif risk_score >= 0.40 or flags_count >= 1:
                verdict = "SUSPICIOUS"
                is_phishing = True
            else:
                verdict = "BENIGN"
                is_phishing = False

            results.append({
                "url": u,
                "domain": f_vec.get("domain", ""),
                "verdict": verdict,
                "is_phishing": is_phishing,
                "risk_score": risk_score,
                "ml_probability": round(ml_proba, 4),
                "flags_count": flags_count,
                "heuristic_flags_count": flags_count,
                "override_verdict": override_verdict,
                "fired_rules": fired_rules,
                "feature_vector": f_vec,
            })

        total_batch_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.info(f"Processed batch of {len(urls)} URLs in {total_batch_ms}ms.")
        return results

    # Aliases for API & Test Fixtures calling inspect_urls_batch / inspect_url_batch
    inspect_url_batch = inspect_batch
    inspect_urls_batch = inspect_batch


# Global singleton pipeline instance
_default_pipeline = PhishingPipeline()

# Alias class for backward compatibility with legacy imports
PhishingDetectorPipeline = PhishingPipeline


# Standalone functional API wrappers
def evaluate_url(
    url: str, 
    config: Optional[Dict[str, Any]] = None, 
    include_features: bool = True
) -> Dict[str, Any]:
    """Standalone wrapper around default pipeline single-URL inspection."""
    return _default_pipeline.inspect_url(url, config=config, include_features=include_features)


def evaluate_url_batch(
    urls: List[str], 
    config: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """Standalone wrapper around default pipeline batch-URL inspection."""
    return _default_pipeline.inspect_batch(urls, config=config)


def update_heuristic_config(config: Dict[str, Any]) -> None:
    """Standalone wrapper to update default pipeline heuristic configuration."""
    _default_pipeline.update_heuristic_config(config)