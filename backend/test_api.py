"""
Test suite for Backend API, SQLite database, and CNN-LSTM Detector
"""
import os
import sys

# Ensure backend directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from main import app
from database import init_db, insert_scan, get_history, get_stats, clear_history
from detector import get_model, run_detection, get_model_info

client = TestClient(app)


def test_database_operations():
    print("Testing SQLite database operations...")
    init_db()
    clear_history()
    
    # Insert test record
    rec = insert_scan(
        filename="test_sample.exe",
        file_type="PE Binary",
        file_size_bytes=1024,
        sha256="abc123def456",
        prediction="Malware",
        confidence=95.5,
        raw_score=0.955,
        threshold=0.5,
        platform="Windows PE"
    )
    assert rec.id is not None
    
    # Query history
    history = get_history(10)
    assert len(history) == 1
    assert history[0]["filename"] == "test_sample.exe"
    assert history[0]["prediction"] == "Malware"

    # Query stats
    stats = get_stats()
    assert stats["total_scans"] == 1
    assert stats["malware_detected"] == 1
    print(" Database operations verified successfully!")


def test_model_loading_and_detection():
    print("Testing model loading and inference...")
    model = get_model()
    assert model is not None, "Model failed to load!"

    # Read test malware image
    test_img_path = os.path.join(os.path.dirname(__file__), "..", "test_malware.png")
    assert os.path.isfile(test_img_path), "test_malware.png not found"
    
    with open(test_img_path, "rb") as f:
        img_bytes = f.read()

    res = run_detection(img_bytes, "test_malware.png", threshold=0.5)
    assert res["status"] == "success"
    assert res["prediction"] in ["Malware", "Benign"]
    assert 0.0 <= res["raw_score"] <= 1.0
    assert 0.0 <= res["confidence"] <= 100.0
    assert len(res["sha256"]) == 64
    print(f" Model inference verified! Result: {res['prediction']}, Score: {res['raw_score']}, Conf: {res['confidence']}%")


def test_api_endpoints():
    print("Testing FastAPI endpoints...")
    # 1. Health check
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"
    assert res.json()["model_loaded"] is True

    # 2. Model info
    res = client.get("/api/model-info")
    assert res.status_code == 200
    assert res.json()["architecture"] == "Hybrid CNN-LSTM"

    # 3. Scan file
    test_img_path = os.path.join(os.path.dirname(__file__), "..", "test_malware.png")
    with open(test_img_path, "rb") as f:
        files = {"file": ("test_malware.png", f, "image/png")}
        data = {"threshold": "0.5"}
        res = client.post("/api/scan", files=files, data=data)
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "success"
    assert "prediction" in body
    assert "gradcam_base64" in body

    # 4. History
    res = client.get("/api/history")
    assert res.status_code == 200
    assert len(res.json()) >= 1

    # 5. Stats
    res = client.get("/api/stats")
    assert res.status_code == 200
    assert res.json()["total_scans"] >= 1

    # 6. APK rejection
    fake_apk = b"PK\x03\x04test_apk"
    res = client.post("/api/scan", files={"file": ("malicious.apk", fake_apk, "application/octet-stream")})
    assert res.status_code == 400
    assert "Android APK detection is pending model verification" in res.json()["detail"]

    print(" All API endpoints verified successfully!")


if __name__ == "__main__":
    test_database_operations()
    test_model_loading_and_detection()
    test_api_endpoints()
    print("\n ALL TESTS PASSED SUCCESSFULLY! ")

