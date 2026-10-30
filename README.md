# Vektor — Cross-Platform Hybrid CNN-LSTM Malware Detection System

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.15%2B-FF6F00.svg?logo=tensorflow&logoColor=white)](https://www.tensorflow.org/)
[![React](https://img.shields.io/badge/React-19.0-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-3.4-38B2AC.svg?logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![SQLite](https://img.shields.io/badge/SQLite-3.0-003B57.svg?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)

**Vektor** is an enterprise-grade deep learning threat detection system that classifies malicious binaries across **Windows PE executables** (`.exe`, `.dll`, `.sys`) and **Android application packages** (`.apk`). Rather than relying on easily circumvented hash databases or rigid heuristics, Vektor integrates spatial **1D Convolutional Neural Networks (Conv1D)** with temporal **Long Short-Term Memory (LSTM)** recurrent networks to extract non-linear opcode clusters and long-range sequential execution dependencies.

---

## Architecture Overview

```
                      Raw Binary Input (.exe / .dll / .apk)
                                      │
                 Feature Extraction & Dimensional Normalization
             ┌────────────────────────┴────────────────────────┐
             ▼                                                 ▼
   Windows PE (244 Features)                       Android APK (487 Features)
   • Static PE Headers & Sections                  • Manifest Permissions
   • Dynamic Cuckoo API Trace                      • KronoDroid Dynamic System Calls
             │                                                 │
             └────────────────────────┬────────────────────────┘
                                      ▼
                   Conv1D Feature Extraction Layer
                   32 Spatial Filters (Kernel Size = 5)
                                      │
                                      ▼
                         Max Pooling 1D (Pool = 2)
                                      │
                                      ▼
                   LSTM Sequence Processing Unit
                   32 Memory Cells (Spatial Dropout = 0.3)
                                      │
                                      ▼
                       Fully Connected Dense Layer
                       Sigmoid Probability Output [0.0 - 1.0]
                                      │
                                      ▼
                 Dynamic Sensitivity Threshold Gate
                   [0.10 High Sensitivity ⟷ 0.90 High Precision]
                                      │
                                      ▼
             Forensic Classification Verdict & SQLite Audit Trail
```

---

## Empirical Benchmark Validation Results

Evaluated rigorously on completely held-out test splits.

| Evaluation Metric | Windows PE Platform (UCI staDyn) | Android APK Platform (KronoDroid) |
|:---|:---:|:---:|
| **Input Feature Dimensionality** | **244 Tabular Features** | **487 Tabular Features** |
| **ROC-AUC Score** | **99.54%** | **95.31%** |
| **Held-Out Test Accuracy** | **97.97%** | **91.14%** |
| **Precision** | **99.76%** | **92.48%** |
| **Recall / Sensitivity** | **98.00%** | **90.38%** |
| **F1-Score** | **98.87%** | **91.42%** |
| **Trainable Weights** | **9,601 Parameters** | **9,601 Parameters** |
| **Evaluation Dataset Size** | 6,248 Samples | 41,262 Real-Device Samples |
| **Held-Out Test Confusion Matrix** | **831 TP / 88 TN / 2 FP / 17 FN** | **3,749 TP / 3,678 TN / 305 FP / 399 FN** |

---

## Core Capabilities & Features

### 1. Multi-Page Cyber Console
- **Scanner Sub-Page (`Scanner`)**:
  - Manual binary upload dropzone for `.exe`, `.dll`, `.sys`, `.apk`, and byte image matrices.
  - Interactive **Confidence Sensitivity Threshold Slider** (`0.10` to `0.90`) allowing analysts to calibrate sensitivity vs. precision in real time.
  - Side-by-side balanced 50/50 layout displaying real-time detection verdict, confidence percentage, raw probability score, SHA-256 cryptographic checksum, and execution latency.
  - Standby inference pipeline specs when awaiting input.
- **Audit History Sub-Page (`Scan History`)**:
  - Full-width SQLite audit trail table.
  - Instant real-time text search by target filename or SHA-256 hash.
  - Filter pills for `All`, `Threats`, and `Clean` classifications with record deletion capabilities.
- **Telemetry & Analytics Sub-Page (`Analytics`)**:
  - Dynamic telemetry metrics tracking total scans, quarantined threats, validated clean software, and average confidence.
  - Glowing animated threat distribution progress bar and runtime telemetry diagnostics.
- **Model Architecture Sub-Page (`Model Specs`)**:
  - Side-by-side held-out validation cards for Windows PE and Android KronoDroid benchmarks with full confusion matrices and 4-stage neural execution breakdown.

### 2. Explainable AI (XAI) with Grad-CAM
- Gradient-weighted Class Activation Mapping (Grad-CAM) computes saliency gradients on PE byte matrices, highlighting the precise structural clusters that influenced the model's classification.

### 3. Strict Authentication & Role Guarding
- Secure SQLite user management with cryptographic password hashing.
- Full name registration, password security criteria validation (minimum length, lowercase, uppercase, numbers, symbols), and interactive password visibility toggles (`EyeIcon`).
- Complete session isolation: Dashboard features only a **Sign Out** button that clears local session state and redirects to the landing page with zero back-channel leaks.

### 4. Claymorphic Design Language
- Ultra-sleek cybersecurity UI engineered with Tailwind CSS and custom claymorphic elevation.
- Built on the Dopely Signal Red palette (`#FF2E2E`, `#8B1111`, `#090909`, `#141010`, `#FFFFFF`, `#B8B1AA`).
- Wide 1700px layout eliminating empty lateral gutters and optimizing multi-monitor analyst workflows.

---

## Project Structure

```
HCLCP/
├── backend/                              # FastAPI REST Inference & Database Engine
│   ├── database.py                       # SQLite schema, user auth, and scan history audit
│   ├── lbrce_pipeline.py                 # UCI staDyn & KronoDroid Conv1D-LSTM models
│   ├── main.py                           # REST endpoints (/scan, /auth, /history, /stats)
│   ├── windows_stadyn_model.keras        # Trained Windows PE Conv1D-LSTM weights
│   ├── android_kronodroid_model.keras    # Trained Android KronoDroid Conv1D-LSTM weights
│   ├── scans.db                          # SQLite persistent audit & user database
│   └── requirements.txt                  # Python runtime dependencies
│
├── frontend/                             # React 19 + Vite Cyber Console
│   ├── src/
│   │   ├── components/
│   │   │   └── VektorLogo.jsx            # High-fidelity SVG shield brand emblem
│   │   ├── App.jsx                       # Multi-page dashboard, tabs, and auth modal
│   │   ├── index.css                     # Claymorphic elevation & cyber animations
│   │   └── main.jsx                      # React DOM root entrypoint
│   ├── public/
│   │   ├── hero-bg.png                   # High-res transparent emblem backdrop
│   │   └── logo.png                      # App favicon & header icon
│   ├── package.json
│   ├── tailwind.config.js
│   └── vite.config.js
│
├── modelFinal/
│   └── best_model.keras                  # Visual 32x32 PE byte image model
├── Sample_Test_Files/                    # Validation test samples for manual evaluation
├── run_backend.bat                       # One-click FastAPI backend launcher
├── run_frontend.bat                      # One-click Vite frontend launcher
└── README.md                             # System documentation
```

---

## Getting Started

### Prerequisites
- **Python**: Version 3.10 or higher
- **Node.js**: Version 18.0 or higher
- **Git**

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Modepalli-Ravindra/Vektor.git
   cd Vektor
   ```

2. **Set up and start the Backend:**
   ```bash
   # Option A: Using the Windows batch script
   run_backend.bat

   # Option B: Manual setup
   cd backend
   python -m venv venv
   source venv/Scripts/activate     # Windows
   pip install -r requirements.txt
   python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
   ```
   *The FastAPI server starts at `http://127.0.0.1:8000` (API documentation at `/docs`).*

3. **Set up and start the Frontend:**
   ```bash
   # Option A: Using the Windows batch script
   run_frontend.bat

   # Option B: Manual setup
   cd frontend
   npm install
   npm run dev
   ```
   *The React console opens at `http://127.0.0.1:5173`.*

---

## Authentication & Usage

1. Open `http://127.0.0.1:5173` in your browser.
2. Click **Sign Up** to create an analyst account (enter Full Name, Email, and Password compliant with security requirements).
3. Once authenticated, access the multi-page dashboard:
   - **Scanner**: Switch between **Windows PE**, **Android APK**, or **Visual Byte Matrix**. Adjust the sensitivity threshold and drop a binary to inspect forensic classifications.
   - **Scan History**: Review and search the persistent SQLite detection audit log.
   - **Analytics**: Inspect real-time threat rates, intercepted telemetry, and database statuses.
   - **Model Specs**: Review neural layer architectures and held-out test confusion matrices.
4. Click **Sign Out** to securely exit the console and return to the landing page.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Author

**Modepalli Ravindra**  
- **GitHub**: [@Modepalli-Ravindra](https://github.com/Modepalli-Ravindra)  
- **Repository**: [https://github.com/Modepalli-Ravindra/Vektor](https://github.com/Modepalli-Ravindra/Vektor)
