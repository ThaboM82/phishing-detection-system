import time
import requests

BASE_URL = "http://localhost:8000"

TEST_PAYLOADS = {
    "legitimate": "https://www.google.com",
    "suspicious": "http://login-verification-secure-account.com/login.php",
    "ip_based": "http://192.168.1.1/admin/login",
    "batch": [
        "https://github.com",
        "http://paypal-security-update-fix.com",
        "http://10.0.0.1/verify"
    ]
}


def check_health() -> bool:
    """Check service health and model initialization status."""
    print(" [1/5] Checking Service Health...")
    try:
        res = requests.get(f"{BASE_URL}/health", timeout=5)
        if res.status_code == 200:
            data = res.json()
            print(f"   Status: {data.get('status')} | Model Loaded: {data.get('model_loaded')}")
            return True
        print(f"   Health check failed with HTTP {res.status_code}")
        return False
    except requests.exceptions.ConnectionError:
        print("   Connection error: Ensure your FastAPI app or Docker container is running.")
        return False


def test_inspection():
    """Test single and batch URL inspection endpoints."""
    print("\n [2/5] Testing URL Inspection Endpoints...")
    
    # 1. Single inspection
    payload = {"url": TEST_PAYLOADS["suspicious"]}
    start = time.time()
    res = requests.post(f"{BASE_URL}/api/v1/inspect", json=payload, timeout=10)
    latency = (time.time() - start) * 1000
    print(f"   Single Inspection Status: {res.status_code} ({latency:.1f}ms)")
    if res.status_code == 200:
        data = res.json()
        print(f"   Verdict: {data.get('verdict')} | ML Prob: {data.get('ml_probability')} | Flags: {data.get('heuristic_flags_count')}")

    # 2. Batch inspection
    batch_payload = {"urls": TEST_PAYLOADS["batch"]}
    start = time.time()
    res_batch = requests.post(f"{BASE_URL}/api/v1/inspect/batch", json=batch_payload, timeout=15)
    batch_latency = (time.time() - start) * 1000
    print(f"   Batch Inspection Status: {res_batch.status_code} ({batch_latency:.1f}ms)")
    if res_batch.status_code == 200:
        print(f"   Processed {len(res_batch.json())} items successfully.")


def test_config():
    """Fetch current rules config, update parameters, and verify synchronization."""
    print("\n [3/5] Testing Heuristic Configuration Engine...")
    
    # Get current config
    res = requests.get(f"{BASE_URL}/api/v1/config", timeout=5)
    if res.status_code != 200:
        print(f"   Failed to fetch config: HTTP {res.status_code}")
        return
    
    current_config = res.json()
    print(f"   Current Max URL Length: {current_config.get('max_url_length')}")

    # Update config (e.g. adjust threshold slightly)
    updated_payload = current_config.copy()
    updated_payload["max_url_length"] = 80
    
    put_res = requests.put(f"{BASE_URL}/api/v1/config", json=updated_payload, timeout=5)
    print(f"   Config Update Status: {put_res.status_code}")
    if put_res.status_code == 200:
        print(f"   Updated Max URL Length to: {put_res.json().get('max_url_length')}")


def test_telemetry():
    """Verify telemetry logs and aggregate telemetry statistics."""
    print("\n [4/5] Testing Telemetry & Analytics Endpoints...")
    
    # Fetch scan audit log
    res_logs = requests.get(f"{BASE_URL}/api/v1/telemetry?limit=5", timeout=5)
    print(f"   Telemetry Logs Status: {res_logs.status_code}")
    if res_logs.status_code == 200:
        logs = res_logs.json()
        print(f"   Retrieved {len(logs)} recent audit log entries.")

    # Fetch telemetry statistics summary
    res_stats = requests.get(f"{BASE_URL}/api/v1/telemetry/stats", timeout=5)
    print(f"   Telemetry Stats Status: {res_stats.status_code}")
    if res_stats.status_code == 200:
        stats = res_stats.json()
        print(f"   Total Scans: {stats.get('total_scans')}")
        print(f"   Phishing Ratio: {stats.get('phishing_ratio_percentage')}%")
        print(f"   Average ML Probability: {stats.get('avg_ml_probability')}")


def test_hot_reload():
    """Test hot-reloading pipeline artifacts dynamically."""
    print("\n [5/5] Testing Dynamic Model Reload...")
    res = requests.post(f"{BASE_URL}/api/v1/model/reload", timeout=10)
    print(f"   Model Reload Status: {res.status_code}")
    if res.status_code == 200:
        print(f"   Response: {res.json().get('message')}")


if __name__ == "__main__":
    print("=" * 60)
    print("  HYBRID PHISHING DETECTION API - COMPREHENSIVE TEST SUITE")
    print("=" * 60)
    
    if check_health():
        test_inspection()
        test_config()
        test_telemetry()
        test_hot_reload()
        print("\n All suite checks completed.")
    else:
        print("\n Health check failed. Skipping test suite execution.")