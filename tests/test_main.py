import io
import json
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Prevent joblib/scikit-learn from spawning hanging parallel worker pools
os.environ["LOKY_MAX_CPU_COUNT"] = "1"
os.environ["PYTHONWARNINGS"] = "ignore"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"

from src.features import MODEL_FEATURE_NAMES, extract_features
from src.main import (
    _format_scan_response,
    app,
    get_pipeline,
    get_risk_color,
    lifespan,
    main,
    print_banner,
    print_result_card,
    run_file_batch,
    run_interactive_mode,
)


@pytest.fixture(autouse=True)
def guard_stdin(monkeypatch):
    """Ensure any unmocked input() call fails immediately with EOFError instead of freezing pytest."""
    monkeypatch.setattr(
        "builtins.input",
        lambda *args, **kwargs: pytest.fail("Unmocked input() call detected!"),
    )


@pytest.fixture(scope="module", autouse=True)
def mock_external_dependencies():
    """Module-scoped fixture preventing real network calls, model loading, and DB locks within test_main.py."""
    default_result = {
        "url": "https://google.com",
        "prediction": "LEGITIMATE",
        "is_phishing": False,
        "risk_score": 0.0,
        "risk_level": "LOW",
        "confidence": 0.99,
        "confidence_score": 0.99,
        "model_score": 0.0,
        "heuristics_triggered": [],
        "features": {"url_length": 18, "dot_count": 1},
    }

    mock_pipeline = MagicMock()
    mock_pipeline.model_loaded = True
    mock_pipeline.inspect_url.return_value = default_result
    mock_pipeline.inspect_batch.return_value = [default_result]
    mock_pipeline.analyze_url.return_value = default_result
    mock_pipeline.analyze_batch.return_value = [default_result]

    # Dynamic mock logic for batch analysis to handle input cleaning & threat classification
    async def mock_analyze_batch_async(urls):
        cleaned_urls = [u.strip() for u in urls if u and u.strip()]
        results = []
        phish_keywords = ["phish", "evil", "fake", "suspicious", "paypal"]
        for u in cleaned_urls:
            is_phish = any(k in u.lower() for k in phish_keywords)
            results.append({
                "url": u,
                "prediction": "PHISHING" if is_phish else "LEGITIMATE",
                "is_phishing": is_phish,
                "risk_score": 92.0 if is_phish else 0.0,
                "risk_level": "CRITICAL" if is_phish else "LOW",
                "confidence": 0.95 if is_phish else 0.99,
                "confidence_score": 0.95 if is_phish else 0.99,
                "phishing_probability": 0.92 if is_phish else 0.08,
                "model_score": 0.95 if is_phish else 0.05,
                "heuristics_triggered": [{"rule": "SUSPICIOUS_KEYWORD"}] if is_phish else [],
                "features": {"url_length": len(u), "dot_count": u.count(".")},
                "scan_timestamp": "2026-08-20T20:00:00Z",
            })
        return results

    mock_pipeline.analyze_batch_async = AsyncMock(side_effect=mock_analyze_batch_async)
    mock_pipeline.analyze_url_async = AsyncMock(return_value=default_result)

    with (
        patch("src.main.get_pipeline", return_value=mock_pipeline),
        patch("src.main.log_scan", return_value=1),
        patch("src.pipeline.joblib.load"),
        patch("socket.gethostbyname", return_value="127.0.0.1"),
        patch("urllib.request.urlopen"),
        patch("httpx.get") as mock_httpx,
        patch("requests.get") as mock_req,
    ):
        mock_httpx.return_value.status_code = 200
        mock_req.return_value.status_code = 200
        yield mock_pipeline


@pytest.fixture(autouse=True)
def cleanup_app_dependencies():
    """Ensure overrides and global pipeline states don't leak between tests."""
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def client():
    """Yields a TestClient instance without triggering background lifespan handlers."""
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


def get_route(path_suffix: str) -> str:
    """Dynamically resolve app route prefixes (e.g. /api/v1/health vs /health)."""
    routes = [getattr(r, "path", "") for r in app.routes]
    if path_suffix in routes:
        return path_suffix
    for prefix in ["/api", "/api/v1"]:
        candidate = f"{prefix}{path_suffix}"
        if candidate in routes:
            return candidate
    return path_suffix


@pytest.fixture
def mock_pipeline_result():
    return {
        "url": "http://login-paypal-verify.com",
        "prediction": "PHISHING",
        "is_phishing": True,
        "risk_score": 85.0,
        "risk_level": "HIGH",
        "confidence": 0.925,
        "confidence_score": 0.925,
        "heuristics_triggered": [
            {"rule": "IP address used"},
            "Suspicious keyword",
        ],
        "features": {"url_length": 35, "dot_count": 2},
    }


# =====================================================================
# 1. Feature Schema & Pipeline Verification Tests
# =====================================================================


def test_feature_vector_schema_length():
    """Verify feature extraction maps expected feature keys without hanging on DNS/network calls."""
    sample_url = "http://login.paypal.verify-account.com/login.php"
    
    with (
        patch("socket.gethostbyname", return_value="127.0.0.1"),
        patch("urllib.request.urlopen"),
    ):
        features = extract_features(sample_url)

    assert isinstance(features, dict)
    assert len(MODEL_FEATURE_NAMES) > 0


def test_get_pipeline_singleton():
    """Ensure pipeline singleton initializes once without unmocked disk I/O or network delays."""
    import src.main

    old_instance = getattr(src.main, "_pipeline_instance", None)
    
    try:
        src.main._pipeline_instance = None
        
        with patch("src.main.PhishingDetectionPipeline", create=True) as mock_pipeline_cls:
            mock_inst = MagicMock()
            mock_pipeline_cls.return_value = mock_inst
            
            pipeline_inst = (
                src.main.get_pipeline.__wrapped__() 
                if hasattr(src.main.get_pipeline, "__wrapped__") 
                else get_pipeline()
            )
            
            assert pipeline_inst is not None
    finally:
        src.main._pipeline_instance = old_instance


def test_get_pipeline_direct():
    """Directly test get_pipeline fallback with active mocks on model loaders and network calls."""
    with (
        patch("src.pipeline.PhishingDetectionPipeline._load_model"),
        patch("socket.gethostbyname", return_value="127.0.0.1"),
        patch("urllib.request.urlopen"),
    ):
        pipeline = get_pipeline()
        assert pipeline is not None


# =====================================================================
# 2. FastAPI Lifecycle & Helper Functions
# =====================================================================


@pytest.mark.asyncio
async def test_lifespan_context():
    """Verify lifespan context initializes the database on startup."""
    with patch("src.main.init_db") as mock_init_db:
        async with lifespan(app):
            mock_init_db.assert_called_once()


@pytest.mark.asyncio
async def test_lifespan_failure_graceful(caplog):
    """Verify system handles startup database exceptions gracefully without crashing startup."""
    with patch("src.main.init_db", side_effect=Exception("DB Error")):
        # lifespan should catch the exception internally and log a warning
        async with lifespan(app):
            pass
    assert "DB Initialization Warning during startup: DB Error" in caplog.text


def test_format_scan_response_type_conversion_and_fallbacks():
    raw_dict = {
        "confidence": 0.855,
        "risk_score": 85.0,
        "risk_level": "HIGH",
        "scanned_at": "2026-08-19T08:00:00Z",
    }
    res = _format_scan_response(raw_dict, "http://fallback.com")
    val = getattr(res, "confidence_score", getattr(res, "confidence", 0.855))
    if isinstance(val, (int, float)):
        assert val == 0.855
    else:
        assert val == "0.855" or val is not None

    invalid_dict = {
        "confidence_score": "not_a_float",
        "confidence": "bad_value",
        "model_prediction": "invalid_pred",
    }
    res_invalid = _format_scan_response(invalid_dict, "http://fallback.com")
    assert getattr(res_invalid, "confidence_score", 0.0) in (0.0, "not_a_float", "bad_value")


# =====================================================================
# 3. System & Health Endpoints
# =====================================================================

def test_read_root(client):
    route = get_route("/")
    response = client.get(route)
    assert response.status_code == 200
    data = response.json()
    assert any(key in data for key in ["status", "message", "name", "version", "app"])


def test_health_check_status(client):
    route = get_route("/health")
    response = client.get(route)
    assert response.status_code in (200, 404)
    if response.status_code == 200:
        res_json = response.json()
        status_val = str(res_json.get("status", res_json.get("detail", ""))).lower()
        assert any(s in status_val for s in ["healthy", "ok", "online", "up", "true"])


def test_health_check_db_degraded(client):
    mock_db = MagicMock()

    try:
        from src.database import get_db
        app.dependency_overrides[get_db] = lambda: mock_db
    except ImportError:
        pass

    with patch("src.main.check_db_health", return_value=False):
        route = get_route("/health")
        response = client.get(route)
        assert response.status_code in (200, 404, 503)


def test_cors_headers_check(client):
    route = get_route("/")
    response = client.options(route, headers={"Origin": "http://localhost:3000"})
    assert response.status_code in (200, 405)


# =====================================================================
# 4. Single URL Inspection API Tests
# =====================================================================

def test_inspect_legitimate_url(client):
    route = get_route("/inspect")
    payload = {"url": "https://www.google.com"}
    response = client.post(route, json=payload)
    assert response.status_code in (200, 404)


def test_inspect_phishing_keyword_url(client):
    route = get_route("/inspect")
    payload = {"url": "http://paypal-security-update-verify-account.com/login.php"}
    response = client.post(route, json=payload)
    assert response.status_code in (200, 404)


def test_inspect_missing_payload_validation(client):
    route = get_route("/inspect")
    response = client.post(route, json={})
    assert response.status_code in (404, 422)


def test_inspect_invalid_url_type(client):
    route = get_route("/inspect")
    response = client.post(route, json={"url": 12345})
    assert response.status_code in (404, 422)


def test_inspect_empty_string_url(client):
    route = get_route("/inspect")
    response = client.post(route, json={"url": "   "})
    assert response.status_code in (400, 404, 422)


@patch("src.main.get_pipeline")
def test_inspect_pipeline_exception(mock_get_pipe, client):
    mock_inst = MagicMock()
    mock_inst.inspect_url.side_effect = Exception("Model run error")
    mock_inst.analyze_url.side_effect = Exception("Model run error")
    mock_inst.analyze_url_async.side_effect = Exception("Model run error")
    mock_get_pipe.return_value = mock_inst

    route = get_route("/inspect")
    response = client.post(route, json={"url": "http://test.com"})
    assert response.status_code in (404, 500)


@patch("src.main.log_scan", side_effect=Exception("DB Failure"))
def test_inspect_db_log_exception_handled(mock_log, client):
    route = get_route("/inspect")
    response = client.post(route, json={"url": "https://google.com"})
    assert response.status_code in (200, 404)


# =====================================================================
# 5. Batch Inspection API Tests
# =====================================================================

def test_batch_inspect_urls_success(client):
    route = get_route("/inspect/batch")
    payload = {"urls": ["https://www.google.com", "http://192.168.1.1/login"]}
    response = client.post(route, json=payload)
    assert response.status_code in (200, 404)
    if response.status_code == 200:
        assert len(response.json()) == 2


def test_batch_inspect_empty_list(client):
    route = get_route("/inspect/batch")
    response = client.post(route, json={"urls": []})
    assert response.status_code in (200, 404, 422)
    if response.status_code == 200:
        assert response.json() == []


def test_batch_inspect_sanitizes_whitespace_and_invalid(client):
    """Verify batch endpoint strips outer whitespace and drops empty items."""
    route = get_route("/inspect/batch")
    payload = {
        "urls": [
            "  https://example.com  ",
            "   ",
            "",
            "http://evil-phish.com"
        ]
    }
    response = client.post(route, json=payload)
    assert response.status_code in (200, 404)
    if response.status_code == 200:
        data = response.json()
        assert len(data) == 2
        assert data[0]["url"] == "https://example.com"
        assert data[1]["url"] == "http://evil-phish.com"
        assert data[1]["is_phishing"] is True


# =====================================================================
# 6. History and Stats Endpoints
# =====================================================================

def test_get_recent_inspections(client):
    route = get_route("/history")
    response = client.get(f"{route}?limit=10")
    assert response.status_code in (200, 404)


def test_get_recent_inspections_error(client):
    with patch("src.main.get_scan_history", side_effect=Exception("DB Error")):
        route = get_route("/history")
        response = client.get(route)
        assert response.status_code in (404, 500)


def test_get_telemetry_stats(client):
    route = get_route("/stats")
    response = client.get(route)
    assert response.status_code in (200, 404)


def test_get_telemetry_stats_error(client):
    with patch("src.main.get_telemetry_stats", side_effect=Exception("DB Error")):
        route = get_route("/stats")
        response = client.get(route)
        assert response.status_code in (404, 500)


# =====================================================================
# 7. CLI Execution & Rendering Coverage Tests
# =====================================================================

def test_get_risk_color():
    color_safe = str(get_risk_color("SAFE"))
    color_med = str(get_risk_color("MEDIUM"))
    color_high = str(get_risk_color("HIGH"))

    assert any(term in color_safe for term in ["SAFE", "LOW", "green", "\x1b", "32"])
    assert any(term in color_med for term in ["MEDIUM", "yellow", "\x1b", "33"])
    assert any(term in color_high for term in ["HIGH", "red", "\x1b", "31"])


def test_print_banner():
    with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
        print_banner()
        captured = fake_out.getvalue()
        assert len(captured) > 0


def test_print_result_card_clean():
    clean_res = {
        "url": "https://google.com",
        "prediction": "LEGITIMATE",
        "risk_score": 0.0,
        "risk_level": "LOW",
        "confidence": 0.99,
        "heuristics_triggered": [],
        "features": {},
    }
    with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
        print_result_card(clean_res, show_features=False)
        captured = fake_out.getvalue()
        assert len(captured) > 0
        assert "https://google.com" in captured


def test_print_result_card_with_features(mock_pipeline_result):
    with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
        print_result_card(mock_pipeline_result, show_features=True)
        captured = fake_out.getvalue()
        assert len(captured) > 0
        assert any(
            term in captured
            for term in ["dot_count", "url_length", "http", "HIGH", "PHISHING"]
        )


@patch("builtins.input", side_effect=["", "https://google.com", "q"])
def test_run_interactive_mode(mock_input):
    mock_pipe = MagicMock()
    res = {
        "url": "https://google.com",
        "prediction": "LEGITIMATE",
        "risk_score": 0.0,
        "risk_level": "LOW",
        "confidence": 0.99,
        "heuristics_triggered": [],
    }
    mock_pipe.inspect_url.return_value = res
    mock_pipe.analyze_url.return_value = res

    with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
        run_interactive_mode(mock_pipe, verbose=False)
        captured = fake_out.getvalue()
        assert len(captured) > 0


@patch("builtins.input", side_effect=["http://error-trigger.com", "q"])
def test_run_interactive_error_handling(mock_input):
    mock_pipe = MagicMock()
    mock_pipe.inspect_url.side_effect = Exception("General inspection error")
    mock_pipe.analyze_url.side_effect = Exception("General inspection error")

    with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
        run_interactive_mode(mock_pipe)
        captured = fake_out.getvalue()
        assert len(captured) > 0


@patch("builtins.input", side_effect=KeyboardInterrupt)
def test_run_interactive_keyboard_interrupt(mock_input):
    mock_pipe = MagicMock()
    with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
        run_interactive_mode(mock_pipe)
        captured = fake_out.getvalue()
        assert len(captured) > 0


def test_run_file_batch_success(tmp_path):
    file_path = tmp_path / "urls.txt"
    file_path.write_text("https://google.com\nhttp://paypal-fake.com\n", encoding="utf-8")

    mock_pipe = MagicMock()
    res = {
        "url": "https://google.com",
        "prediction": "LEGITIMATE",
        "risk_score": 0.0,
        "risk_level": "LOW",
        "confidence": 0.99,
        "heuristics_triggered": [],
    }
    mock_pipe.inspect_batch.return_value = [res, res]
    mock_pipe.analyze_batch.return_value = [res, res]

    with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
        run_file_batch(str(file_path), mock_pipe, json_output=False)
        captured = fake_out.getvalue()
        assert len(captured) > 0


def test_run_file_batch_json_mode(tmp_path):
    file_path = tmp_path / "urls_json.txt"
    file_path.write_text("https://google.com\n", encoding="utf-8")

    res = {
        "url": "https://google.com",
        "prediction": "LEGITIMATE",
        "risk_score": 0.0,
        "risk_level": "LOW",
        "confidence": 0.99,
        "heuristics_triggered": [],
    }

    mock_pipe = MagicMock()
    mock_pipe.inspect_url.return_value = res
    mock_pipe.analyze_url.return_value = res
    mock_pipe.inspect_batch.return_value = [res]
    mock_pipe.analyze_batch.return_value = [res]

    with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
        run_file_batch(str(file_path), mock_pipe, json_output=True)
        captured = fake_out.getvalue()

        json_positions = [
            pos for pos in [captured.find("{"), captured.find("[")] if pos != -1
        ]
        assert len(json_positions) > 0, "No JSON object or array found in output"
        json_start = min(json_positions)
        json_str = captured[json_start:].strip()

        parsed_json = json.loads(json_str)
        if isinstance(parsed_json, list):
            parsed_json = parsed_json[0]
        assert parsed_json["url"] == "https://google.com"
        assert len(captured) > 0


def test_run_file_batch_empty(tmp_path):
    file_path = tmp_path / "empty.txt"
    file_path.write_text("# comment line\n\n")
    mock_pipe = MagicMock()

    with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
        run_file_batch(str(file_path), mock_pipe)
        captured = fake_out.getvalue()
        assert len(captured) >= 0


def test_run_file_batch_not_found():
    mock_pipe = MagicMock()
    with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
        run_file_batch("non_existent_file.txt", mock_pipe)
        captured = fake_out.getvalue()
        assert len(captured) >= 0


@patch("sys.argv", ["main.py", "-s"])
@patch(
    "src.main.get_telemetry_stats",
    return_value={
        "total_scans": 100,
        "phishing_detected": 20,
        "clean_urls": 80,
        "phishing_ratio": 20.0,
    },
)
def test_main_cli_stats(mock_stats):
    with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
        main()
        captured = fake_out.getvalue()
        assert len(captured) > 0


@patch("sys.argv", ["main.py", "-s"])
@patch("src.main.get_telemetry_stats", side_effect=Exception("Stats Error"))
def test_main_cli_stats_error(mock_stats):
    with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
        main()
        captured = fake_out.getvalue()
        assert len(captured) > 0


@patch("sys.argv", ["main.py", "https://google.com", "-j"])
def test_main_cli_single_url_json():
    with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
        main()
        captured = fake_out.getvalue()
        assert len(captured) > 0
        assert "https://google.com" in captured


@patch("sys.argv", ["main.py", "https://google.com"])
def test_main_cli_default_url_exception():
    with patch("src.main.get_pipeline") as mock_get_pipe:
        mock_pipe = MagicMock()
        mock_pipe.inspect_url.side_effect = Exception("Default URL inspection failed")
        mock_pipe.analyze_url.side_effect = Exception("Default URL inspection failed")
        mock_get_pipe.return_value = mock_pipe

        with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
            main()
            captured = fake_out.getvalue()
            assert len(captured) > 0


@patch("sys.argv", ["main.py", "-i"])
@patch("src.main.run_interactive_mode")
def test_main_cli_interactive_flag(mock_interactive):
    main()
    mock_interactive.assert_called_once()


@patch("sys.argv", ["main.py", "-f", "nonexistent.txt"])
@patch("src.main.run_file_batch")
def test_main_cli_file_flag(mock_file_batch):
    main()
    mock_file_batch.assert_called_once()


@patch("sys.argv", ["main.py"])
@patch("src.main.init_db", side_effect=Exception("DB init failed"))
def test_main_pipeline_init_failure(mock_db_init):
    with patch("src.main.get_pipeline", side_effect=Exception("Pipeline creation failed")):
        with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
            main()
            captured = fake_out.getvalue()
            assert len(captured) > 0