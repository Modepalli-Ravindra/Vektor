# Malware Detection Using CNN-LSTM

A hybrid deep learning model combining Convolutional Neural Networks (CNN) and Long Short-Term Memory (LSTM) networks to classify Windows PE files as malicious or benign, with Grad-CAM explainability and an adjustable confidence threshold.

---

## Architecture

```
Input (32x32 grayscale PE visualization)
        │
        ▼
Conv2D (filters_1, 3x3, ReLU) + MaxPooling
        │
        ▼
Conv2D (filters_2, 3x3, ReLU) + MaxPooling
        │
        ▼
Conv2D (filters_3, 3x3, ReLU) + MaxPooling
        │
        ▼  Reshape → sequence
LSTM (lstm_units, tanh)
        │
        ▼
Dense (dense_units, ReLU) + Dropout(0.5)
        │
        ▼
Dense(1, Sigmoid) → malware probability [0, 1]
```

Hyperparameters tuned via Keras Tuner (RandomSearch) across:
- Conv filters: 16-256
- LSTM units: 32-128
- Dense units: 64-512
- Learning rate: 1e-3, 1e-4, 1e-5
- Optimizer: Adam, RMSProp, SGD

---

## Dataset

- **Source:** Windows PE files converted to 32x32 grayscale images
- **Distribution:** 49,376 malware / 2,583 benign (imbalanced)
- **Balancing:** SMOTE (Synthetic Minority Over-sampling Technique, strategy=0.95)
- **Split:** 80% train / 20% test (stratified)
- **Augmentation:** Rotation ±20°, zoom 0.2, horizontal flip

---

## Results

| Metric | Value |
|---|---|
| Test Accuracy | ~85%+ |
| Recall (Malware) | 0.99 |
| Precision (Malware) | 0.76 |
| Malware instances detected | 9,882 |

**Note on Precision/Recall tradeoff:** The model is tuned for high recall (0.99) meaning it catches almost all malware, at the cost of some false positives (precision 0.76). The confidence threshold slider in the UI lets you tune this tradeoff for your environment.

---

## Features

### v2 Improvements
- **Confidence threshold slider** -- tune precision/recall tradeoff at inference time without retraining
- **Grad-CAM visualization** -- shows which regions of the PE image activated the model's decision
- **Interpretable UI** -- explains what the threshold means for your detection environment
- **Drag and drop upload** -- improved UX over v1

### Core
- Hybrid CNN-LSTM architecture for spatial + temporal feature extraction
- SMOTE balancing for highly imbalanced malware/benign ratio
- Keras Tuner hyperparameter optimization
- Data augmentation to reduce overfitting
- Saved best model checkpoint via ModelCheckpoint callback

---

## Grad-CAM Explainability

Gradient-weighted Class Activation Mapping highlights which pixels in the PE visualization the CNN layers activated on. This makes the model's decision interpretable -- you can see whether it's focusing on meaningful structural regions of the binary.

---

## Setup

```bash
git clone https://github.com/dhruvvv55/Malware-Detection-using-CNN-LSTM.git
cd Malware-Detection-using-CNN-LSTM

pip install -r requirements.txt

python app.py
# Open http://localhost:5000
```

### Requirements

```
flask>=3.0.0
tensorflow>=2.13.0
Pillow>=10.0.0
numpy>=1.24.0
scikit-learn>=1.3.0
imbalanced-learn>=0.11.0
matplotlib>=3.7.0
keras-tuner>=1.4.0
```

---

## Project Structure

```
Malware-Detection-using-CNN-LSTM/
├── app.py                        # Flask app with Grad-CAM + threshold
├── malware-detection.ipynb       # Training notebook
├── modelFinal/
│   └── best_model.keras          # Saved best model (Keras Tuner checkpoint)
├── templates/
│   └── index.html                # UI with confidence slider
├── output/
│   └── lstm_cnn_malware_detection/ # Keras Tuner trial outputs
└── README.md
```

---

## How It Works

1. PE binary is converted to a 32x32 grayscale image (byte-level visualization)
2. CNN layers extract spatial features from the image structure
3. LSTM layer learns sequential/temporal patterns in the feature maps
4. Final sigmoid outputs a probability score [0, 1]
5. Score is compared against the detection threshold (default 0.5)
6. Grad-CAM computes gradients of the output with respect to the last conv layer to produce a heatmap

---

## Author

**Dhruv Patel** -- MS Cybersecurity Engineering, USC 
