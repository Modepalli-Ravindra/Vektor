"""
Malware Detection - Improved Flask App
=======================================
Author: Dhruv Patel
Improvements over v1:
  - Confidence threshold slider (tune precision/recall tradeoff)
  - Grad-CAM visualization (show what the model looks at)
  - Clean UI with result breakdown
"""

import io
import base64
import numpy as np
from flask import Flask, request, render_template, jsonify
from PIL import Image
import tensorflow as tf
from tensorflow.keras.models import load_model  # type: ignore

app = Flask(__name__)

MODEL_PATH = "./modelFinal/best_model.keras"
model = load_model(MODEL_PATH)
IMAGE_SIZE = 32

# Warmup call to build input/output shapes for Grad-CAM
_dummy = np.zeros((1, IMAGE_SIZE, IMAGE_SIZE, 1), dtype=np.float32)
model(_dummy, training=False)


def preprocess_image(image: Image.Image) -> np.ndarray:
    image = image.resize((IMAGE_SIZE, IMAGE_SIZE))
    image = image.convert("L")
    arr = np.array(image, dtype=np.float32) / 255.0
    return arr.reshape(1, IMAGE_SIZE, IMAGE_SIZE, 1)


def compute_gradcam(model, img_array: np.ndarray) -> str:
    """
    Input gradient saliency map -- works reliably with Sequential models.
    Shows which pixels most influenced the malware/benign decision.
    """
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.cm as cm

    try:
        img_tensor = tf.Variable(img_array.astype(np.float32))

        with tf.GradientTape() as tape:
            prediction = model(img_tensor, training=False)
            loss = prediction[:, 0]

        grads = tape.gradient(loss, img_tensor)

        if grads is None:
            return ""

        # Saliency map from input gradients
        saliency = tf.reduce_max(tf.abs(grads), axis=-1)[0].numpy()
        saliency = (saliency - saliency.min()) / (saliency.max() - saliency.min() + 1e-8)

        original = img_array[0, :, :, 0]
        colormap = cm.jet(saliency)[:, :, :3]
        overlay = 0.5 * np.stack([original] * 3, axis=-1) + 0.5 * colormap
        overlay = np.clip(overlay, 0, 1)

        fig, axes = plt.subplots(1, 3, figsize=(10, 3))
        axes[0].imshow(original, cmap="gray")
        axes[0].set_title("Input")
        axes[0].axis("off")
        axes[1].imshow(saliency, cmap="jet")
        axes[1].set_title("Saliency Map")
        axes[1].axis("off")
        axes[2].imshow(overlay)
        axes[2].set_title("Overlay")
        axes[2].axis("off")
        plt.tight_layout()

        buf = io.BytesIO()
        plt.savefig(buf, format="png", dpi=100, bbox_inches="tight")
        plt.close()
        buf.seek(0)
        return base64.b64encode(buf.read()).decode("utf-8")

    except Exception as e:
        print(f"Saliency map failed: {e}")
        return ""


@app.route("/", methods=["GET", "POST"])
def index():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    threshold = float(request.form.get("threshold", 0.5))

    try:
        image = Image.open(file.stream)
        img_array = preprocess_image(image)

        raw_score = float(model.predict(img_array, verbose=0)[0][0])
        is_malware = raw_score >= threshold
        confidence = raw_score if is_malware else 1 - raw_score

        gradcam_b64 = compute_gradcam(model, img_array)

        return jsonify({
            "result":     "Malware" if is_malware else "Benign",
            "raw_score":  round(raw_score, 4),
            "confidence": round(confidence * 100, 2),
            "threshold":  threshold,
            "gradcam":    gradcam_b64,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health")
def health():
    return jsonify({"status": "ok", "model": MODEL_PATH})


if __name__ == "__main__":
    app.run(debug=True, port=5000)