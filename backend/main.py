"""
FastAPI Backend for Hybrid CNN-LSTM Cross-Platform Malware Detection System
Supports:
- Windows UCI staDyn (244 Tabular Features, Conv1D+LSTM, 9,601 Params, 97.97% Accuracy)
- Android KronoDroid (487 Static+Dynamic Features, Conv1D+LSTM, 9,601 Params, 91.14% Accuracy)
- SQLite Forensic Audit Trail
"""
import os
import hashlib
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import numpy as np
from pydantic import BaseModel

from database import (
    init_db,
    insert_scan,
    get_history,
    get_stats,
    clear_history,
    create_user,
    authenticate_user,
    reset_password
)
from detector import run_detection as run_visual_detection, get_model_info as get_visual_model_info
from lbrce_pipeline import (
    extract_pe_features_244,
    extract_apk_features_487,
    predict_windows_sample,
    predict_android_sample,
    get_windows_artifacts,
    get_android_artifacts,
    CURATED_TEST_SAMPLES,
)

# Initialize SQLite database schema
init_db()

app = FastAPI(
    title="Hybrid CNN-LSTM Cross-Platform Malware Detection System",
    description="LBRCE Specification: Cross-Platform Android & Windows Malware Detection using Hybrid CNN-LSTM",
    version="3.0.0"
)

# CORS configuration to allow React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB limit


@app.on_event("startup")
async def startup_event():
    # Warm up both Windows staDyn and Android KronoDroid models
    get_windows_artifacts()
    get_android_artifacts()


@app.get("/")
def root():
    return {
        "system": "Hybrid CNN-LSTM Cross-Platform Malware Detection System",
        "platforms": ["Windows (UCI staDyn 244)", "Android (KronoDroid 487)"],
        "status": "online",
        "docs": "/docs"
    }


@app.get("/api/health")
def health_check():
    win_model, _ = get_windows_artifacts()
    and_model, _ = get_android_artifacts()
    return {
        "status": "healthy" if (win_model and and_model) else "degraded",
        "windows_stadyn_model": win_model is not None,
        "android_kronodroid_model": and_model is not None,
        "database": "sqlite_connected",
        "platforms_active": ["Windows", "Android"]
    }


@app.get("/api/college-metrics")
def get_college_metrics():
    """
    Returns the official LBRCE held-out experimental metrics.
    """
    return {
        "windows": {
            "dataset": "UCI staDyn (6,248 samples: 595 benign, 5,653 malware)",
            "features": "244 (PE-header static + Cuckoo dynamic measurements)",
            "model_architecture": "Conv1D (32, 5) + MaxPool1D (2) + LSTM (32, 0.3) + Dense (32) + Sigmoid",
            "trainable_parameters": 9601,
            "metrics": {
                "accuracy": "97.97%",
                "malware_precision": "99.76%",
                "malware_recall": "98.00%",
                "malware_f1": "98.87%",
                "roc_auc": "99.54%",
                "benign_recall": "98.00%"
            },
            "confusion_matrix": {
                "true_benign": 88,
                "true_malware": 831,
                "false_malware": 2,
                "false_benign": 17,
                "test_total": 938
            }
        },
        "android": {
            "dataset": "KronoDroid (142,112 samples)",
            "features": "487 (Permissions, components + Dynamic syscalls: read, write, execve)",
            "model_architecture": "Conv1D (32, 5) + MaxPool1D (2) + LSTM (32, 0.3) + Dense (32) + Sigmoid",
            "trainable_parameters": 9601,
            "metrics": {
                "accuracy": "91.14%",
                "malware_precision": "92.48%",
                "malware_recall": "90.38%",
                "malware_f1": "91.42%",
                "roc_auc": "95.31%"
            },
            "confusion_matrix": {
                "true_benign": 13271,
                "true_malware": 14221,
                "false_malware": 1157,
                "false_benign": 1514,
                "test_total": 30163
            }
        }
    }


@app.get("/api/test-samples")
def get_curated_samples():
    """
    Returns curated held-out test samples for 1-click viva/faculty evaluation.
    """
    return [
        {
            "id": k,
            "platform": v["platform"],
            "name": v["name"],
            "type": v["type"],
            "description": v["description"],
            "expected": v["expected"]
        }
        for k, v in CURATED_TEST_SAMPLES.items()
    ]


@app.post("/api/scan/test-sample/{sample_id}")
def evaluate_test_sample(sample_id: str, threshold: float = 0.5):
    item = CURATED_TEST_SAMPLES.get(sample_id)
    if not item:
        for k, v in CURATED_TEST_SAMPLES.items():
            if v.get("id") == sample_id:
                item = v
                break
    if not item:
        raise HTTPException(status_code=404, detail="Sample not found")
    feats = np.array(item["features"], dtype=np.float32)

    if item["platform"] == "windows":
        res = predict_windows_sample(feats, item["name"], threshold)
    else:
        res = predict_android_sample(feats, item["name"], threshold)

    sha = hashlib.sha256(item["name"].encode()).hexdigest()
    res["sha256"] = sha
    res["file_size_bytes"] = len(feats) * 4

    insert_scan(
        filename=item["name"],
        file_type=f"{item['platform'].title()} Test Vector",
        file_size_bytes=res["file_size_bytes"],
        sha256=sha,
        prediction=res["prediction"],
        confidence=res["confidence"],
        raw_score=res["raw_score"],
        threshold=res["threshold"],
        platform=res["platform"]
    )
    return res


@app.post("/api/scan")
async def scan_file(
    file: UploadFile = File(...),
    platform: str = Form("windows"),
    threshold: float = Form(0.5)
):
    if threshold < 0.01 or threshold > 0.99:
        raise HTTPException(status_code=400, detail="Threshold must be between 0.01 and 0.99")

    filename = file.filename or "unknown_file"
    ext = os.path.splitext(filename.lower())[1]
    contents = await file.read()

    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty (0 bytes).")
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File exceeds 50MB limit.")

    sha256 = hashlib.sha256(contents).hexdigest()

    # Route based on platform selection or extension
    if platform.lower() == "android" or ext == ".apk":
        # ANDROID KronoDroid EVALUATION
        features = extract_apk_features_487(contents)
        result = predict_android_sample(features, filename, threshold)
        result["sha256"] = sha256
        result["file_size_bytes"] = len(contents)

        insert_scan(
            filename=filename,
            file_type="Android APK",
            file_size_bytes=len(contents),
            sha256=sha256,
            prediction=result["prediction"],
            confidence=result["confidence"],
            raw_score=result["raw_score"],
            threshold=result["threshold"],
            platform="Android (KronoDroid)"
        )
        return result

    else:
        # WINDOWS UCI staDyn EVALUATION
        # If user uploaded image, can also provide Grad-CAM saliency
        if ext in [".png", ".jpg", ".jpeg", ".bmp"]:
            vis_result = run_visual_detection(contents, filename, threshold)
            features = np.frombuffer(contents[:244*4], dtype=np.uint8)[:244].astype(np.float32)
            if len(features) < 244:
                features = np.pad(features, (0, 244 - len(features)))
            win_res = predict_windows_sample(features, filename, threshold)
            win_res["gradcam_base64"] = vis_result.get("gradcam_base64", "")
            result = win_res
        else:
            features = extract_pe_features_244(contents)
            result = predict_windows_sample(features, filename, threshold)

        result["sha256"] = sha256
        result["file_size_bytes"] = len(contents)

        insert_scan(
            filename=filename,
            file_type="Windows PE (.exe/.dll)",
            file_size_bytes=len(contents),
            sha256=sha256,
            prediction=result["prediction"],
            confidence=result["confidence"],
            raw_score=result["raw_score"],
            threshold=result["threshold"],
            platform="Windows (UCI staDyn)"
        )
        return result


@app.get("/api/history")
def scan_history(limit: int = 50):
    return get_history(limit)


@app.get("/api/stats")
def dashboard_stats():
    return get_stats()


@app.delete("/api/history")
def reset_history():
    clear_history()
    return {"message": "Scan history cleared successfully"}


class RegisterPayload(BaseModel):
    full_name: str = ""
    email: str
    password: str


class AuthPayload(BaseModel):
    email: str
    password: str


class ForgotPasswordPayload(BaseModel):
    email: str
    new_password: str


@app.post("/api/auth/register")
def register_user(payload: RegisterPayload):
    user, error = create_user(payload.email, payload.password, payload.full_name)
    if error:
        raise HTTPException(status_code=400, detail=error)
    return {"status": "success", "user": user}


@app.post("/api/auth/login")
def login_user(payload: AuthPayload):
    user, error = authenticate_user(payload.email, payload.password)
    if error:
        raise HTTPException(status_code=401, detail=error)
    return {"status": "success", "user": user}


@app.post("/api/auth/forgot-password")
def reset_user_password(payload: ForgotPasswordPayload):
    success, message = reset_password(payload.email, payload.new_password)
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return {"status": "success", "message": message}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
