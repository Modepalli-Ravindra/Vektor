"""
Model detector and inference pipeline for Hybrid CNN-LSTM Windows Malware Detection
"""
import io
import os
import math
import base64
import time
import hashlib
import numpy as np
from PIL import Image

# Suppress noisy TF logs
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"

import tensorflow as tf
from tensorflow.keras.models import load_model  # type: ignore

IMAGE_SIZE = 32

# Path to model file
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_CANDIDATES = [
    os.path.join(CURRENT_DIR, "..", "modelFinal", "best_model.keras"),
    os.path.join(CURRENT_DIR, "modelFinal", "best_model.keras"),
    os.path.join(os.getcwd(), "modelFinal", "best_model.keras"),
]

MODEL_PATH = None
for candidate in MODEL_CANDIDATES:
    if os.path.isfile(candidate):
        MODEL_PATH = os.path.abspath(candidate)
        break

_model = None
_model_load_error = None


def get_model():
    global _model, _model_load_error
    if _model is not None:
        return _model
    if MODEL_PATH is None:
        _model_load_error = "best_model.keras was not found in expected modelFinal directory"
        return None
    try:
        _model = load_model(MODEL_PATH)
        # Warmup pass
        dummy = np.zeros((1, IMAGE_SIZE, IMAGE_SIZE, 1), dtype=np.float32)
        _model(dummy, training=False)
        return _model
    except Exception as e:
        _model_load_error = f"Failed to load model: {str(e)}"
        return None


def pe_bytes_to_image(data: bytes) -> Image.Image:
    """
    Safely converts raw PE executable bytes into a 32x32 grayscale Image.
    Uses standard malware binary-to-grayscale visualization (Nataraj method).
    DOES NOT EXECUTE the binary.
    """
    total_bytes = len(data)
    if total_bytes == 0:
        return Image.new("L", (IMAGE_SIZE, IMAGE_SIZE), color=0)

    # Determine width by binary size
    kb = total_bytes / 1024.0
    if kb < 10:
        width = 32
    elif kb < 30:
        width = 64
    elif kb < 60:
        width = 128
    elif kb < 100:
        width = 256
    elif kb < 200:
        width = 384
    elif kb < 500:
        width = 512
    elif kb < 1000:
        width = 768
    else:
        width = 1024

    # Calculate required length for full rows
    height = int(math.ceil(total_bytes / width))
    pad_needed = (height * width) - total_bytes
    if pad_needed > 0:
        data = data + b"\x00" * pad_needed

    arr = np.frombuffer(data, dtype=np.uint8).reshape((height, width))
    img = Image.fromarray(arr, mode="L")
    return img.resize((IMAGE_SIZE, IMAGE_SIZE), Image.Resampling.BILINEAR)


def preprocess_file_input(file_bytes: bytes, filename: str) -> np.ndarray:
    """
    Preprocess uploaded file into model input tensor shape: (1, 32, 32, 1), normalized to [0, 1].
    """
    ext = os.path.splitext(filename.lower())[1]

    if ext in [".png", ".jpg", ".jpeg", ".bmp", ".webp"]:
        # Direct grayscale image or visual representation
        img = Image.open(io.BytesIO(file_bytes))
        img = img.resize((IMAGE_SIZE, IMAGE_SIZE))
        img = img.convert("L")
    else:
        # PE Binary or raw executable byte stream (.exe, .dll, .sys, .bin)
        img = pe_bytes_to_image(file_bytes)

    arr = np.array(img, dtype=np.float32) / 255.0
    return arr.reshape(1, IMAGE_SIZE, IMAGE_SIZE, 1)


def compute_gradcam(model, img_array: np.ndarray) -> str:
    """
    Generates Grad-CAM / Input Saliency heatmap visualization as base64 PNG.
    """
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.cm as cm
        img_tensor = tf.Variable(img_array.astype(np.float32))

        with tf.GradientTape() as tape:
            prediction = model(img_tensor, training=False)
            loss = prediction[:, 0]

        grads = tape.gradient(loss, img_tensor)
        if grads is None:
            return ""

        saliency = tf.reduce_max(tf.abs(grads), axis=-1)[0].numpy()
        saliency = (saliency - saliency.min()) / (saliency.max() - saliency.min() + 1e-8)

        original = img_array[0, :, :, 0]
        colormap = cm.jet(saliency)[:, :, :3]
        overlay = 0.5 * np.stack([original] * 3, axis=-1) + 0.5 * colormap
        overlay = np.clip(overlay, 0, 1)

        fig, axes = plt.subplots(1, 3, figsize=(10, 3.2), facecolor="#0B132B")
        for ax in axes:
            ax.set_facecolor("#0B132B")

        axes[0].imshow(original, cmap="gray")
        axes[0].set_title("Input (32x32)", color="#00F0FF", fontsize=11, fontweight="bold")
        axes[0].axis("off")

        axes[1].imshow(saliency, cmap="jet")
        axes[1].set_title("Saliency Map", color="#FF007F", fontsize=11, fontweight="bold")
        axes[1].axis("off")

        axes[2].imshow(overlay)
        axes[2].set_title("Feature Overlay", color="#00FF66", fontsize=11, fontweight="bold")
        axes[2].axis("off")

        plt.tight_layout()

        buf = io.BytesIO()
        plt.savefig(buf, format="png", dpi=110, bbox_inches="tight", facecolor=fig.get_facecolor(), edgecolor="none")
        plt.close(fig)
        buf.seek(0)
        return base64.b64encode(buf.read()).decode("utf-8")
    except Exception as e:
        print(f"Grad-CAM generation error: {e}")
        return ""


def run_detection(file_bytes: bytes, filename: str, threshold: float = 0.5):
    """
    Perform safe malware detection inference.
    """
    model = get_model()
    if model is None:
        return {
            "error": _model_load_error or "Model is not loaded",
            "status": "failed"
        }

    start_time = time.time()
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    file_size = len(file_bytes)

    # Preprocessing
    img_array = preprocess_file_input(file_bytes, filename)

    # Predict
    preds = model.predict(img_array, verbose=0)
    raw_score = float(preds[0][0])

    is_malware = raw_score >= threshold
    confidence = (raw_score if is_malware else (1.0 - raw_score)) * 100.0

    # Explainability
    gradcam_b64 = compute_gradcam(model, img_array)
    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    return {
        "status": "success",
        "filename": filename,
        "file_size_bytes": file_size,
        "sha256": sha256,
        "prediction": "Malware" if is_malware else "Benign",
        "is_malware": is_malware,
        "confidence": round(confidence, 2),
        "raw_score": round(raw_score, 4),
        "threshold": round(threshold, 2),
        "gradcam_base64": gradcam_b64,
        "execution_time_ms": elapsed_ms,
        "platform": "Windows PE"
    }


def get_model_info():
    model = get_model()
    return {
        "model_loaded": model is not None,
        "model_path": MODEL_PATH,
        "architecture": "Hybrid CNN-LSTM",
        "input_shape": [32, 32, 1],
        "total_layers": len(model.layers) if model else 0,
        "default_threshold": 0.5,
        "supported_platforms": {
            "windows": {
                "status": "active",
                "extensions": [".exe", ".dll", ".bin", ".sys", ".png", ".jpg", ".jpeg"]
            },
            "android": {
                "status": "pending_verification",
                "message": "Android APK model and bytecode extraction pipeline are not yet verified."
            }
        }
    }
