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

### 2. Explainable AI (XAI) with SHAP & Grad-CAM
- **SHAP (SHapley Additive exPlanations)**: Calculates game-theoretic feature attribution across Windows PE (244 tabular attributes: PE headers, sections, Cuckoo native API calls) and Android APK (487 tabular attributes: dangerous permissions, KronoDroid dynamic system calls). Returns net marginal impact scores, directional attribution badges (`Benign Factor (-)` vs `Malware Factor (+)`), and plain-English forensic domain reasons.
- **Zero-Scroll Sub-Tab Toggle**: Result cards feature an instant inline toggle between **Forensic Overview** (metadata, checksum, Conv1D/LSTM assessment) and **SHAP Explainability** (feature attribution rankings with compact scroll), ensuring zero page scrollbar and perfectly balanced card heights.
- **Grad-CAM Saliency Maps**: Gradient-weighted Class Activation Mapping computes heatmaps on PE byte matrices, highlighting the precise structural byte clusters that influenced the model's classification.

### 3. Cyber Scanning Loader with Blur Backdrop
- During inference execution, the application renders a fullscreen `backdrop-blur-md bg-black/75` focus overlay.
- Features animated rotating cyber radar rings, volumetric pulsing glows, floating brand emblem, and a 5-stage live pipeline execution tracker with dynamic gradient progress bars.

### 4. Strict Authentication & Role Guarding
- Secure SQLite user management with cryptographic password hashing.
- Full name registration, password security criteria validation (minimum length, lowercase, uppercase, numbers, symbols), and interactive password visibility toggles (`EyeIcon`).
- Complete session isolation: Dashboard features only a **Sign Out** button that clears local session state and redirects to the landing page with zero back-channel leaks.

### 5. Ultra-Wide Claymorphic Design Language
- Ultra-sleek cybersecurity UI engineered with Tailwind CSS and custom claymorphic elevation.
- Built on the Dopely Signal Red palette (`#FF2E2E`, `#8B1111`, `#090909`, `#141010`, `#FFFFFF`, `#B8B1AA`).
- Ultra-wide 1850px layout with prominent active red borders on selected navbar pages and generous vertical breathing room.

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

## Getting Started & Installation on Another System

Follow this step-by-step guide to clone, install, and run Vektor on another computer (Windows, Linux, or macOS).

### System Prerequisites & Supported Versions

| Dependency | Minimum Version | Recommended / Tested Version | Verification Command | Download Link |
|:---|:---:|:---:|:---:|:---|
| **Git** | `2.30.0+` | `2.40.0+` | `git --version` | [git-scm.com](https://git-scm.com/) |
| **Python** | `3.10.0+` | `3.10` – `3.13` (Tested on `3.13.15`) | `python --version` | [python.org](https://www.python.org/downloads/) |
| **Node.js** | `18.0.0+` LTS | `20.x` or `22.x` (Tested on `22.23.2`) | `node --version` | [nodejs.org](https://nodejs.org/) |
| **npm** | `9.0.0+` | `10.9.0+` | `npm --version` | Bundled with Node.js |

> [!IMPORTANT]
> When installing Python on Windows, ensure you check the box **"Add Python to PATH"** in the installer.

---

### Step-by-Step Installation Guide

#### Step 1: Clone the Repository via Git
Open your terminal (PowerShell, Command Prompt, or Bash) and clone the repository:
```bash
git clone https://github.com/Modepalli-Ravindra/Vektor.git
cd Vektor
```

#### Step 2: Set Up Backend (Python Virtual Environment & Dependencies)
Create an isolated Python virtual environment and install all required machine learning and API libraries:

**On Windows (PowerShell / Command Prompt):**
```bash
# 1. Create a Python virtual environment
python -m venv venv

# 2. Activate the virtual environment
venv\Scripts\activate

# 3. Upgrade pip
python -m pip install --upgrade pip

# 4. Install backend dependencies (FastAPI, TensorFlow, Keras, pefile, etc.)
pip install -r backend/requirements.txt
```

**On Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements.txt
```

#### Step 3: Set Up Frontend (Node.js & Vite Dependencies)
Install the React dependencies:
```bash
cd frontend
npm install
cd ..
```

#### Step 4: Generate Demo Test Files (Optional)
Generate clean Windows `.exe`, Android `.apk`, and Byte Matrix simulation files for immediate testing:
```bash
python create_sample_files.py
```
*(This generates 5 safe demonstration files into `Sample_Test_Files/` ready to upload to the scanner).*

---

### Running the Application

You will run the **Backend API** and **Frontend UI** in two separate terminal windows.

#### Option A: Quick One-Click Launchers (Windows)
- Double-click `run_backend.bat` (Starts FastAPI server on `http://127.0.0.1:8000`)
- Double-click `run_frontend.bat` (Starts React Vite server on `http://127.0.0.1:5173`)

#### Option B: Manual Command-Line Launch

**Terminal 1 — Start Backend Server:**
```bash
# Ensure your virtual environment is active
venv\Scripts\activate      # Windows
# or: source venv/bin/activate  # Linux/macOS

cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
*Backend will start on `http://127.0.0.1:8000` with interactive API docs at `http://127.0.0.1:8000/docs`.*

**Terminal 2 — Start Frontend Server:**
```bash
cd frontend
npm run dev
```
*Frontend will launch on `http://127.0.0.1:5173`.*

---

### Accessing & Using the System

1. Open your browser and navigate to: **`http://127.0.0.1:5173`**
2. **Sign Up / Sign In**:
   - Click **Sign Up** to create an analyst account (enter Full Name, Email, and a strong password).
   - Or click **Sign In** if you already created an account.
3. **Scan a File**:
   - Navigate to the **Scanner** tab.
   - Choose your platform: **Windows PE (244 Features)**, **Android APK (487 Features)**, or **Visual Byte Matrix**.
   - Drag & drop or select a file from `Sample_Test_Files/` (e.g. `1_Clean_hostname.exe` or `3_Suspicious_Trojan_Spyware.apk`).
   - Adjust the **Classification Threshold Slider** (default: `0.50`).
   - Click **Scan & Classify Binary**.
4. **Inspect Results with Zero Scroll**:
   - Watch the animated **Cyber Scanning Loader** with backdrop blur and live 5-stage neural pipeline tracking.
   - View the Verdict on the right card: toggle between **Forensic Overview** and **SHAP Explainability** right on the card without vertical page scrolling.
5. **Explore Multi-Page Analytics**:
   - Check **Scan History** for persistent SQLite audit trails.
   - Check **Analytics** for live telemetry and threat distribution bars.
   - Check **Model Specs** for model architecture and validation confusion matrices.
6. Click **Sign Out** in the top navbar when finished.

---

## Troubleshooting & Common Setup Errors

If you encounter an issue when setting up Vektor on a new computer, use the instant fixes below:

### 1. PowerShell Script Execution Disabled
- **Error:** `venv\Scripts\activate : File ...\activate.ps1 cannot be loaded because running scripts is disabled on this system.`
- **Cause:** Windows PowerShell restricts script execution by default.
- **Fix:** Open PowerShell and run this one-time command:
  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
  ```
  *Alternatively, use Windows Command Prompt (`cmd`) and run:* `venv\Scripts\activate.bat`

### 2. `'python'` or `'pip'` Not Recognized
- **Error:** `'python' is not recognized as an internal or external command...`
- **Cause:** Python was installed without enabling the PATH environment variable.
- **Fix:** 
  1. Open Windows "Add or Remove Programs" ➔ Find **Python** ➔ Click **Modify**.
  2. Check the box **"Add Python to environment variables"** and complete setup.
  3. Close and reopen your terminal.

### 3. `'node'` or `'npm'` Not Recognized
- **Error:** `'node' is not recognized as an internal or external command...`
- **Cause:** Node.js is not installed or terminal hasn't refreshed.
- **Fix:** Download and install Node.js LTS from [nodejs.org](https://nodejs.org/), then restart your terminal.

### 4. Port 8000 or Port 5173 Already in Use
- **Error:** `[WinError 10048] Only one usage of each socket address is normally permitted`
- **Cause:** Another background instance of Uvicorn or another app is holding port 8000.
- **Fix:** Stop the existing process holding the port:
  ```powershell
  # Windows PowerShell:
  Get-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess | Stop-Process -Force
  ```

### 5. Frontend Shows "Unable to connect to the backend server"
- **Cause:** The backend server is not running or still initializing.
- **Fix:** Keep the **Backend terminal window open and running** (`run_backend.bat`). Wait until you see `Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)` before performing scans.

### 6. TensorFlow GPU Notice on Windows
- **Notice:** `WARNING:tensorflow:TensorFlow GPU support is not available on native Windows for TensorFlow >= 2.11`
- **Resolution:** This is a benign informational warning from Google TensorFlow, not an error. The Vektor neural architectures (9,601 weights) are optimized for ultra-fast sub-30ms CPU inference. You can safely ignore this notice.

### 7. Need Safe Test Samples for Evaluation
- **Resolution:** If the new computer does not have sample `.exe` or `.apk` files, run:
  ```bash
  python create_sample_files.py
  ```
  This creates 5 safe evaluation binaries in `Sample_Test_Files/` ready for upload.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Author

**Modepalli Ravindra**  
- **GitHub**: [@Modepalli-Ravindra](https://github.com/Modepalli-Ravindra)  
- **Repository**: [https://github.com/Modepalli-Ravindra/Vektor](https://github.com/Modepalli-Ravindra/Vektor)
