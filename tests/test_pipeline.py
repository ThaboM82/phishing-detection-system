"""
tests/test_pipeline.py

Unit and integration tests for the PhishingDetectionPipeline, model loading,
risk scoring, batch execution, and diagnostic health features.
"""

import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

# Ensure both project root and 'src' directory are in Python search path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")

for path in (PROJECT_ROOT, SRC_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

from src.pipeline import (
    PhishingDetectionPipeline,
    PhishingDetectorPipeline,
    predict_url,
)


@pytest.fixture
def dummy_pipeline():
    """Provides an uninitialized pipeline running in fallback mode."""
    with patch.object(PhishingDetectionPipeline, "_load_model", return_value=None):
        yield PhishingDetectionPipeline(model_path="non_existent.pkl")


@pytest.fixture
def mock_ml_model():
    """Provides a base mock ML model configured with expected feature dimensions."""
    model = MagicMock()
    model.n_features_in_ = 17
    return model


@pytest.fixture
def mocked_ml_pipeline(mock_ml_model):
    """Provides a pipeline loaded with an active mock ML model."""
    mock_ml_model.predict_proba.return_value = [[0.1, 0.9]]  # 90% phishing probability

    with patch.object(PhishingDetectionPipeline, "_load_model", return_value=mock_ml_model):
        pipeline = PhishingDetectionPipeline(model_path="dummy_path.pkl")
        yield pipeline, mock_ml_model


@pytest.fixture
def mock_pipeline_model():
    """Provides an isolated mocked scikit-learn model."""
    model = MagicMock()
    model.predict.return_value = [0]  # Legitimate
    model.predict_proba.return_value = [[0.95, 0.05]]
    return model


# =====================================================================
# 1. Pipeline Initialization & Model Loading Tests
# =====================================================================


def test_alias_compatibility():
    """Verify PhishingDetectorPipeline is an exact alias of PhishingDetectionPipeline."""
    assert PhishingDetectorPipeline is PhishingDetectionPipeline


def test_load_model_missing_file_fallback():
    """Ensure pipeline falls back gracefully to heuristic mode when model file is missing."""
    pipeline = PhishingDetectionPipeline(model_path="non_existent_file_xyz.pkl")
    assert pipeline.model is None


def test_load_model_joblib_fallback():
    """Verify joblib loader fallback when standard pickle loading fails."""
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tmp:
        tmp_path = tmp.name
        tmp.write(b"invalid pickle binary content")

    try:
        mock_joblib_model = MagicMock()
        with patch("joblib.load", return_value=mock_joblib_model), patch(
            "pickle.load", side_effect=Exception("Pickle load failed")
        ):
            pipeline = PhishingDetectionPipeline(model_path=tmp_path)
            assert pipeline.model is mock_joblib_model
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_pipeline_initialization_with_model(mock_pipeline_model):
    """Verify pipeline loads model correctly when path exists."""
    with patch("pathlib.Path.exists", return_value=True), patch(
        "pathlib.Path.is_file", return_value=True
    ), patch("os.path.exists", return_value=True), patch(
        "joblib.load", return_value=mock_pipeline_model
    ):
        pipeline = PhishingDetectionPipeline(model_path="dummy_path.pkl")
        assert getattr(pipeline, "is_model_loaded", pipeline.model is not None) is True


def test_pipeline_model_load_failure_fallback():
    """Verify graceful fallback to heuristic engine if joblib fails to load model file."""
    with patch("os.path.exists", return_value=True), patch(
        "joblib.load", side_effect=Exception("Corrupted model file")
    ):
        pipeline = PhishingDetectionPipeline(model_path="corrupted.pkl")
        assert getattr(pipeline, "is_model_loaded", pipeline.model is not None) is False

        # Pipeline should still inspect URLs using heuristic fallback
        result = pipeline.inspect_url("http://paypal-verify-account.com")
        assert isinstance(result, dict)
        assert "prediction" in result or "is_phishing" in result


# =====================================================================
# 2. Risk Tier Scoring Tests
# =====================================================================


@pytest.mark.parametrize(
    "score, expected_level",
    [
        (90.0, "CRITICAL"),
        (85.0, "CRITICAL"),
        (80.0, "CRITICAL"),
        (79.9, "HIGH"),
        (70.0, "HIGH"),
        (65.0, "HIGH"),
        (64.9, "MEDIUM"),
        (55.0, "MEDIUM"),
        (40.0, "MEDIUM"),
        (35.0, "MEDIUM"),
        (34.9, "LOW"),
        (20.0, "LOW"),
        (0.0, "LOW"),
    ],
)
def test_determine_risk_level(dummy_pipeline, score, expected_level):
    """Verify risk tier assignment matches score thresholds and signature parameters."""
    is_phishing = score >= 35.0
    ml_prob = score / 100.0
    assert (
        dummy_pipeline._determine_risk_level(score, is_phishing, ml_prob)
        == expected_level
    )


# =====================================================================
# 3. Single URL Inspection & Analysis Tests
# =====================================================================


def test_inspect_url_invalid_input(dummy_pipeline):
    """Verify invalid inputs return structured error response payloads cleanly."""
    result_empty = dummy_pipeline.inspect_url("")
    assert result_empty["status"] == "error"
    assert result_empty["is_phishing"] is False
    assert result_empty["risk_score"] == 0.0

    result_spaces = dummy_pipeline.inspect_url("   ")
    assert result_spaces["status"] == "error"

    result_none = dummy_pipeline.inspect_url(None)
    assert result_none["status"] == "error"


def test_inspect_whitelisted_clean_url(dummy_pipeline):
    """Ensure legitimate whitelisted URLs yield 0 risk score and LOW risk level."""
    result = dummy_pipeline.inspect_url("https://www.google.com")

    assert result["status"] == "success"
    assert result["prediction"] == "LEGITIMATE"
    assert result["is_phishing"] is False
    assert result["risk_score"] == 0.0
    assert result["risk_level"] == "LOW"


def test_inspect_url_with_ml_model(mocked_ml_pipeline):
    """Verify probability calculation when ML model is active."""
    pipeline, mock_model = mocked_ml_pipeline
    result = pipeline.inspect_url("http://paypal-verification-alert.com")

    assert result["status"] == "success"
    assert result["is_phishing"] is True
    assert result["prediction"] == "PHISHING"
    assert result["model_score"] == 0.9
    mock_model.predict_proba.assert_called_once()


def test_inspect_url_model_fallback_prediction(dummy_pipeline, mock_ml_model):
    """Verify model prediction fallback using predict when predict_proba is absent."""
    mock_model = MagicMock(spec=["predict", "n_features_in_"])
    mock_model.n_features_in_ = 17
    mock_model.predict.return_value = [1]  # Binary classification result
    dummy_pipeline.model = mock_model

    result = dummy_pipeline.inspect_url("http://suspicious-target.com")
    assert result["status"] == "success"
    assert result["model_score"] == 1.0


def test_inspect_url_model_exception_graceful_handling(dummy_pipeline, mock_ml_model):
    """Ensure model evaluation exceptions default safely without crashing analysis."""
    mock_ml_model.predict_proba.side_effect = Exception("Inference memory fault")
    dummy_pipeline.model = mock_ml_model

    result = dummy_pipeline.inspect_url("http://example.com")
    assert result["status"] == "success"
    assert result["model_score"] == 0.0  # Safe default fallback score on model error


def test_inspect_url_legitimate(mock_pipeline_model):
    """Test single URL analysis for a safe domain."""
    with patch("os.path.exists", return_value=True), patch(
        "joblib.load", return_value=mock_pipeline_model
    ):
        pipeline = PhishingDetectionPipeline(model_path="dummy.pkl")
        result = pipeline.inspect_url("https://www.google.com")

        assert result["is_phishing"] is False
        assert result["risk_level"] in ("LOW", "SAFE")


def test_inspect_url_phishing_heuristics_trigger(mock_pipeline_model):
    """Verify high-risk heuristic keywords force phishing detection."""
    mock_pipeline_model.predict.return_value = [1]
    mock_pipeline_model.predict_proba.return_value = [[0.10, 0.90]]

    with patch("os.path.exists", return_value=True), patch(
        "joblib.load", return_value=mock_pipeline_model
    ):
        pipeline = PhishingDetectionPipeline(model_path="dummy.pkl")
        result = pipeline.inspect_url(
            "http://192.168.1.1/paypal-login-security-update.php"
        )

        assert result["is_phishing"] is True
        assert result["risk_level"] in ("HIGH", "CRITICAL")


# =====================================================================
# 4. Batch Processing Tests & Async Execution
# =====================================================================


def test_inspect_batch_urls(dummy_pipeline):
    """Verify processing multiple URLs through inspect_batch / analyze_batch."""
    urls = ["https://google.com", "http://192.168.1.1/login"]
    results = dummy_pipeline.inspect_batch(urls)

    assert len(results) == 2
    assert results[0]["url"] == "https://google.com"
    assert results[1]["url"] == "http://192.168.1.1/login"


def test_inspect_batch_urls_with_mock_model(mock_pipeline_model):
    """Verify synchronous batch inspection processes multiple inputs correctly."""
    with patch("os.path.exists", return_value=True), patch(
        "joblib.load", return_value=mock_pipeline_model
    ):
        pipeline = PhishingDetectionPipeline(model_path="dummy.pkl")
        urls = [
            "https://www.google.com",
            "http://evil-phish-login.com",
            "https://github.com",
        ]
        results = pipeline.inspect_batch(urls)

        assert isinstance(results, list)
        assert len(results) == 3
        assert all(isinstance(res, dict) for res in results)


def test_analyze_batch_alias(dummy_pipeline):
    """Ensure analyze_batch routes identically to inspect_batch."""
    urls = ["https://google.com"]
    results = dummy_pipeline.analyze_batch(urls)
    assert len(results) == 1
    assert results[0]["url"] == "https://google.com"


@pytest.mark.anyio
async def test_analyze_url_async(dummy_pipeline):
    """Verify asynchronous wrapper execution using anyio plugin."""
    result = await dummy_pipeline.analyze_url_async("https://www.google.com")
    assert result["status"] == "success"
    assert result["url"] == "https://www.google.com"


# =====================================================================
# 5. Diagnostic State & Functional Helper Tests
# =====================================================================


def test_get_health_status(dummy_pipeline):
    """Verify health diagnostic payload structure."""
    status = dummy_pipeline.get_health_status()
    assert "model_loaded" in status
    assert "scaler_loaded" in status
    assert "weights" in status
    assert status["model_loaded"] is False


def test_predict_url_helper():
    """Verify standalone functional helper predict_url works cleanly."""
    with patch.object(PhishingDetectionPipeline, "_load_model", return_value=None):
        res = predict_url("https://www.google.com")
        assert res["status"] == "success"
        assert res["prediction"] == "LEGITIMATE"


# =====================================================================
# 6. Branch & Exception Edge-Case Coverage Expansion
# =====================================================================


def test_load_model_exception_fallback():
    """Hits generic Exception path during model file loading."""
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tmp:
        tmp_path = tmp.name
        tmp.write(b"completely corrupted garbage data")

    try:
        with patch("joblib.load", side_effect=Exception("Joblib failed")), patch(
            "pickle.load", side_effect=Exception("Pickle failed")
        ):
            pipeline = PhishingDetectionPipeline(model_path=tmp_path)
            assert pipeline.model is None
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_pipeline_init_handles_corrupt_and_missing_models(tmp_path):
    """Hits branches where joblib.load fails or file paths are invalid."""
    missing_path = str(tmp_path / "non_existent_model.joblib")
    corrupt_path = tmp_path / "bad_binary.joblib"
    corrupt_path.write_bytes(b"INVALID_HEADER_DATA")

    with patch("joblib.load", side_effect=FileNotFoundError("Model file not found")):
        pipe_missing = PhishingDetectionPipeline(model_path=missing_path)
        assert pipe_missing.model is None

    with patch("joblib.load", side_effect=Exception("Pickle error")):
        pipe_corrupt = PhishingDetectionPipeline(model_path=str(corrupt_path))
        assert pipe_corrupt.model is None


def test_inspect_url_feature_shape_mismatch(dummy_pipeline, mock_ml_model):
    """Hits feature shape padding/truncation when model expects different dimension counts."""
    mock_ml_model.n_features_in_ = 25
    mock_ml_model.predict_proba.return_value = [[0.2, 0.8]]
    dummy_pipeline.model = mock_ml_model

    result = dummy_pipeline.inspect_url("http://example.com")
    assert result["status"] == "success"
    assert result["model_score"] == 0.0


def test_inspect_url_scaler_transform_exception(dummy_pipeline, mock_ml_model):
    """Hits exception block when scaler preprocessing fails during inference."""
    mock_scaler = MagicMock()
    mock_scaler.transform.side_effect = Exception("Scaler dimension mismatch")

    dummy_pipeline.model = mock_ml_model
    dummy_pipeline.scaler = mock_scaler

    result = dummy_pipeline.inspect_url("http://example.com")
    assert result["status"] == "success"
    assert result["is_phishing"] is not None


def test_get_health_status_with_active_model(mocked_ml_pipeline):
    """Hits diagnostic health status reporting when model and scaler are fully loaded."""
    pipeline, _ = mocked_ml_pipeline
    pipeline.scaler = MagicMock()

    status = pipeline.get_health_status()
    assert status["model_loaded"] is True
    assert status["scaler_loaded"] is True


def test_pipeline_model_inference_exception_fallback():
    """Hits fallback branches when model prediction throws unexpected exceptions."""
    pipe = PhishingDetectionPipeline(model_path=None)
    mock_model = MagicMock()

    mock_model.predict_proba.side_effect = ValueError("Feature array shape mismatch")
    mock_model.predict.side_effect = ValueError("Feature array shape mismatch")
    pipe.model = mock_model

    res = pipe.inspect_url("http://192.168.1.1/admin/login.php")
    assert isinstance(res, dict)
    assert res.get("risk_score") is not None or "risk_level" in res


def test_pipeline_handles_incomplete_feature_extraction():
    """Hits branches handling missing feature keys or feature extraction errors."""
    pipe = PhishingDetectionPipeline(model_path=None)

    # Return an empty dict to test safe handling of empty feature sets
    with patch.object(pipe.extractor, "extract_features", return_value={}):
        res = pipe.inspect_url("https://fallback-check.com")
        assert isinstance(res, dict)
        assert res["status"] == "success"

    # Test handling when feature extraction throws an unhandled exception
    with patch.object(pipe.extractor, "extract_features", side_effect=Exception("Extraction crashed")):
        res = pipe.inspect_url("https://extraction-failure.com")
        assert isinstance(res, dict)
        assert res["status"] == "success"


def test_inspect_batch_urls_empty_and_mixed(dummy_pipeline):
    """Hits empty batch evaluation and mixed invalid URL input branches."""
    assert dummy_pipeline.inspect_batch([]) == []

    mixed_urls = [
        "https://valid-target.org",
        "",
        None,
        "ftp://10.0.0.1:8080/admin",
    ]
    res_mixed = dummy_pipeline.inspect_batch(mixed_urls)
    assert isinstance(res_mixed, list)
    assert len(res_mixed) == 4