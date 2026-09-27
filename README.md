<div align="center">

# 🛡️ TrustLens AI

### Intelligent Multi-Format File Trust & Threat Analysis System

*Zero-Execution · Static Analysis · Explainable AI · MITRE ATT&CK Mapping*

---

[![Python](https://img.shields.io/badge/Python-3.14%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.60-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.9-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-Test%20Suite-6b7280?style=for-the-badge&logo=pytest&logoColor=white)](tests/)
[![Accuracy](https://img.shields.io/badge/PE%20Holdout%20Accuracy-99.48%25-6366f1?style=for-the-badge)](docs/ieee_paper.md)
[![Code Style](https://img.shields.io/badge/Code%20Style-Black-000000?style=for-the-badge)](https://black.readthedocs.io/)
[![IEEE Paper](https://img.shields.io/badge/IEEE%20Paper-Draft-00629B?style=for-the-badge&logo=ieee&logoColor=white)](docs/ieee_paper.md)

</div>

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Screenshots](#-screenshots)
- [Installation](#-installation)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Supported File Formats](#-supported-file-formats)
- [How It Works](#-how-it-works)
- [Model Performance](#-model-performance)
- [Future Scope](#-future-scope)
- [Contributing](#-contributing)
- [Research & Citation](#-research--citation)
- [License](#-license)

---

## 🔍 Overview

**TrustLens AI** is a B.Tech research prototype, web-based file security analysis system that performs **zero-execution static threat analysis** across multiple file formats before they are opened or executed.

Instead of running suspicious files in sandboxes (which introduce latency and are vulnerable to evasion), TrustLens inspects the **structural anatomy** of files — headers, entropy, macros, embedded objects, and metadata — to generate an intuitive **Trust Score** (0–100%) and **Risk Category** (Safe / Low / Medium / High / Critical).

The system is built on a **modular Plugin Architecture**, where each file format is handled by a dedicated analyzer. Features are normalized into a uniform **10-Dimensional Common Feature Vector** and scored by a trained **Random Forest classifier**. All predictions are backed by a **local explainability engine** that generates human-readable reasons and maps selected static structural indicators to potential MITRE ATT&CK® associations using heuristic contextual rules.

> 🎓 This project was developed as a B.Tech final-year capstone in Computer Science & Engineering (Data Science) at **Annamacharya Institute of Technology and Sciences (Autonomous), Rajampet**.

---

## ✨ Key Features

| Feature | Description |
|:---|:---|
| 🔌 **Plugin Architecture** | Every file format is handled by an independent, swappable `BaseAnalyzer` plugin — add new formats without touching core logic |
| 🧠 **Dual ML Pipeline** | Deep 54-feature PE classifier for executables; 10-feature multi-format Random Forest for all other documents |
| 📊 **Trust Score Engine** | 0–100% Trust Score mapped to 5 risk tiers: Safe / Low / Medium / High / Critical |
| 💡 **Explainable AI (XAI)** | Feature contribution engine generates natural-language reasons for every prediction — no black-box outputs |
| 🎯 **MITRE ATT&CK Mapping** | Selected static structural indicators mapped to potential MITRE ATT&CK® associations using heuristic contextual rules |
| 📄 **PDF Security Reports** | ReportLab-compiled, printable PDF reports with full scan results, reasons, and recommendations |
| 📈 **Scan Dashboard** | Session-scoped statistics, full scan history, risk distribution charts, and confidence heatmaps |
| 🏋️ **Suspicious File Backtesting** | Built-in evaluation suite for benchmarking model performance against known threat payloads |
| 🧪 **Test suite available** | Full pytest suite covering analyzers, pipeline, prediction engine, PDF reports, and preprocessing |
| ✅ **PEP 8 Compliant** | Black-formatted, isort-sorted, flake8-validated codebase |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        TRUSTLENS AI                             │
│                  Multi-Format Threat Scanner                    │
└─────────────────────────┬───────────────────────────────────────┘
                          │  Binary Stream (any file type)
                          ▼
              ┌───────────────────────┐
              │   Plugin Dispatcher   │  ← Detects extension + magic bytes
              └───────────┬───────────┘
          ┌───────────────┼──────────────────────────────┐
          ▼               ▼               ▼              ▼
    ┌──────────┐    ┌──────────┐   ┌──────────┐   ┌──────────┐
    │   PDF    │    │  Office  │   │   PE     │   │ Script / │
    │ Analyzer │    │ Analyzer │   │ Analyzer │   │ Archive  │
    └────┬─────┘    └────┬─────┘   └────┬─────┘   └────┬─────┘
         └───────────────┴──────────────┴───────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Feature Normalizer   │  ← 10-D Common Feature Vector
              └───────────┬───────────┘
                          │
          ┌───────────────┴───────────────┐
          ▼                               ▼
  ┌────────────────┐           ┌──────────────────────┐
  │ PE Deep Model  │           │  Multi-Format Model  │
  │  (54 features) │           │    (10 features)     │
  └────────┬───────┘           └──────────┬───────────┘
           └───────────────────┘
                          │
              ┌───────────┴───────────┐
              │  Explainability +     │  ← Reasons, MITRE ATT&CK T-codes
              │  MITRE ATT&CK Mapper  │
              └───────────┬───────────┘
                          │
              ┌───────────┴───────────┐
              │   Streamlit UI  /     │
              │   PDF Report Output   │
              └───────────────────────┘
```

---

## 📸 Screenshots

> 📌 **Note for contributors:** Application screenshots are provided in the project root and documentation.

| Upload & Predict | Scan Dashboard |
|:---:|:---:|
| ![Upload Page](docs/diagrams/screenshot_upload.png) | ![Dashboard Page](docs/diagrams/screenshot_dashboard.png) |
| *Drag-and-drop file upload with real-time Trust Score, Risk Badge, and Reasons Checklist* | *Session statistics, scan history table, and risk distribution charts* |

| MITRE ATT&CK Mapping | PDF Security Report |
|:---:|:---:|
| ![MITRE Page](docs/diagrams/screenshot_mitre.png) | ![PDF Report](docs/diagrams/screenshot_report.png) |
| *Selected static structural indicators mapped to potential MITRE ATT&CK® associations using heuristic contextual rules* | *Printable PDF report with full scan results and security recommendations* |

---

## ⚙️ Installation

### Requirements

| Dependency | Version |
|:---|:---:|
| Python | `3.14+` |
| scikit-learn | `1.9.0` |
| Streamlit | `1.60.0` |
| pypdf | `6.14.2` |
| reportlab | `4.2.2` |
| pefile | `2024.8.26` |
| numpy | `2.5.1` |
| pandas | `3.0.5` |

### Step 1 — Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/trustlens-ai.git
cd trustlens-ai
```

### Step 2 — Create & Activate Virtual Environment

```bash
# Create
python3 -m venv .venv

# Activate — Linux/macOS
source .venv/bin/activate

# Activate — Windows
.venv\Scripts\activate.bat
```

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Train the Multi-Format Model

```bash
PYTHONPATH=src python src/btech/multiformat_pipeline.py
```

Generated assets:
- `multiformat_model.joblib` — Trained Random Forest classifier
- `multiformat_preprocessor.joblib` — StandardScaler pipeline
- `files/multiformat_metrics.json` — Synthetic evaluation metrics log

### Step 5 — Optional Real-World Validation

The project includes a separate validation layer for independent raw-file testing, while the documented 99.48% PE result is the independent PE holdout validation result.
It accepts labelled benign and malicious files and performs **static analysis only**;
uploaded files are never executed.

For reproducible CLI evaluation, place legally obtained samples in:

```text
data/real_world_dataset/
├── benign/
└── malicious/
```

Then run:

```bash
PYTHONPATH=src python run_real_world_eval.py
```

Results are written to `data/real_world_evaluation/metrics.json` and
`data/real_world_evaluation/file_results.csv`.

The Streamlit application also contains **Real-World Validation** as a separate page.
PE files are routed through the dedicated 54-feature model. The documented PE validation result is **99.48% accuracy on the independent 41,415-sample holdout set**.

> **Evaluation policy:** the existing 99.80% multi-format result is a synthetic
> proof-of-concept holdout result. It must not be presented as universal real-world
> accuracy. Real-world metrics are reported only after an actual labelled corpus is
> evaluated.

---

## 🚀 Usage

### Launch the Web Application

```bash
PYTHONPATH=src streamlit run src/btech/app.py
```

Navigate to `http://localhost:8501` in your browser.

### Run the CLI Scanner

```bash
PYTHONPATH=src python src/btech/main.py
```

### Run the Full Test Suite

```bash
PYTHONPATH=src pytest
```

Run the full test suite locally after installing all project dependencies. Environment-dependent tests may be skipped when optional packages are unavailable.

### Retrain the PE Malware Model

```bash
PYTHONPATH=src python src/btech/pipeline.py
```

---

## 📁 Project Structure

```
trustlens-ai/
├── .env.example                     # Environment variable template
├── .gitignore                       # Git exclusions
├── .python-version                  # Target Python version pin
├── LICENSE                          # MIT License
├── README.md                        # Project documentation
├── pyproject.toml                   # Build & tool configuration
├── requirements.txt                 # Production dependencies
├── requirements-dev.txt             # Dev-only dependencies (black, flake8…)
│
├── config/
│   ├── config.yaml                  # Application-level configuration
│   └── logging.yaml                 # Structured logging configuration
│
├── docs/
│   ├── ieee_paper.md                # IEEE research paper draft
│   ├── project_report.md            # Full academic project report
│   ├── presentation.md              # Slide deck content
│   ├── viva_qna_bank.md             # Viva voce Q&A preparation bank
│   └── diagrams/                    # Architecture & UI diagrams (PNG/SVG)
│
├── files/
│   └── multiformat_metrics.json     # Model evaluation metrics output
│
├── src/
│   ├── btech/
│   │   ├── app.py                   # Streamlit landing page entry point
│   │   ├── main.py                  # CLI entry point
│   │   ├── predict.py               # Dual-model prediction engine
│   │   ├── multiformat_pipeline.py  # Multi-format ML training pipeline
│   │   ├── pipeline.py              # PE malware ML training pipeline
│   │   ├── preprocess.py            # PE feature extraction (54 features)
│   │   ├── evaluation.py            # Model metrics & evaluation
│   │   ├── explanation.py           # XAI feature contribution engine
│   │   ├── report.py                # ReportLab PDF report generator
│   │   ├── save_model.py            # Joblib serialization service
│   │   ├── training.py              # Training orchestrator
│   │   │
│   │   ├── analyzers/               # Plugin analyzer modules
│   │   │   ├── base.py              # BaseAnalyzer abstract interface
│   │   │   ├── pdf.py               # PDF structural analyzer
│   │   │   ├── office.py            # Word/Excel/PowerPoint analyzer
│   │   │   ├── executable.py        # PE binary analyzer (EXE/DLL/SYS)
│   │   │   ├── archive.py           # ZIP/RAR/APK analyzer
│   │   │   ├── script.py            # Script/text analyzer (PS1/JS/PY…)
│   │   │   ├── image.py             # Image EXIF metadata analyzer
│   │   │   └── normalization.py     # 10-D Common Feature Vector mapper
│   │   │
│   │   └── pages/
│   │       ├── 01_Upload_Predict.py # Upload & scan interface
│   │       ├── 02_Dashboard.py      # Statistics & scan history
│   │       ├── 03_MITRE_ATTACK.py   # ATT&CK tactic mapping view
│   │       └── 04_About.py          # System reference & glossary
│   │
│   ├── feature_engineering/
│   │   ├── static_analyzer.py       # Legacy static analysis utilities
│   │   └── feature_engineering.py   # Feature construction pipeline
│   │
│   ├── metadata/
│   │   └── metadata.py              # Metadata extraction (pypdf, docx)
│   │
│   └── utils/
│       ├── config.py                # Configuration loader (YAML)
│       ├── constants.py             # System-wide constants
│       ├── logger.py                # Logger setup
│       ├── paths.py                 # Absolute path resolvers
│       └── settings.py              # Application defaults
│
└── tests/
    ├── test_analyzers.py            # Plugin analyzer unit tests
    ├── test_evaluation.py           # Model evaluation tests
    ├── test_explanation.py          # XAI engine tests
    ├── test_feature_engineering.py  # Feature extraction tests
    ├── test_main.py                 # CLI integration tests
    ├── test_metadata.py             # Metadata extraction tests
    ├── test_pipeline.py             # ML pipeline tests
    ├── test_predict.py              # Prediction engine tests
    ├── test_preprocess.py           # PE preprocessing tests
    ├── test_report.py               # PDF report tests
    ├── test_save_model.py           # Model serialization tests
    └── test_training.py             # Training orchestrator tests
```

---

## 📂 Supported File Formats

| Category | Extensions | Analyzer Module |
|:---|:---|:---|
| **PDF Documents** | `.pdf` | `pdf.py` — JS count, URI density, encryption, embedded objects |
| **Word Documents** | `.doc` `.docx` `.docm` | `office.py` — VBA macros, OLE embeds, hidden paragraphs |
| **Excel Spreadsheets** | `.xls` `.xlsx` `.xlsm` | `office.py` — VBA macros, hidden sheets, formula density |
| **PowerPoint Decks** | `.ppt` `.pptx` `.pptm` | `office.py` — macros, embedded media, external link count |
| **Archives** | `.zip` `.rar` `.tar` `.gz` | `archive.py` — nested archives, executable payloads, encryption |
| **Android APKs** | `.apk` | `archive.py` — DEX bytecode, `.so` native libraries |
| **PE Executables** | `.exe` `.dll` `.sys` | `executable.py` + deep `malware_model.joblib` (54 features) |
| **Scripts** | `.ps1` `.js` `.py` `.bat` `.vbs` `.sh` `.cmd` `.msi` | `script.py` — obfuscation, shell commands, base64 payloads |
| **Plain Text / CSV** | `.txt` `.csv` | `script.py` — embedded commands, links, encoded payloads |
| **Images** | `.jpg` `.jpeg` `.png` `.gif` `.bmp` | `image.py` — EXIF metadata completeness, entropy anomalies |

---

## 🔬 How It Works

### 1. Plugin Dispatch
`predict.py` iterates through registered analyzers and selects the first one whose `can_handle(ext, bytes)` returns `True`. This is evaluated at runtime without any hard-coded format routing tables.

### 2. Feature Extraction
The matched analyzer's `extract_features()` method parses the file's structural headers, returning a format-specific feature dictionary.

### 3. Feature Normalization — 10-D Common Feature Vector

| # | Feature | Description |
|:---:|:---|:---|
| 1 | `file_size_kb` | File size in kilobytes |
| 2 | `entropy` | Shannon entropy of file byte distribution |
| 3 | `has_executable_code` | Binary executable code or bytecode present |
| 4 | `has_obfuscation` | Obfuscation patterns or encoding blocks detected |
| 5 | `has_network_indicators` | Embedded URIs, IP addresses, or DNS references |
| 6 | `has_macros_or_scripts` | Active macro or script execution capability |
| 7 | `is_encrypted_or_packed` | Encryption or packer signatures detected |
| 8 | `has_masquerading` | Extension mismatch or magic byte spoofing detected |
| 9 | `metadata_density` | Ratio of present metadata fields to expected total |
| 10 | `suspicious_indicators_count` | Cumulative count of all flagged risk signals |

### 4. Dual-Model Prediction Routing

- **PE Executables (`.exe`, `.dll`, `.sys`)** → `malware_model.joblib` — 54-feature deep PE classifier trained on static feature telemetry (138k samples)
- **All other formats** → `multiformat_model.joblib` — 10-feature multi-format classifier with multi-profile threat synthesis

### 5. Risk Category Mapping

| Trust Score | Risk Category | Recommended Action |
|:---:|:---:|:---|
| ≥ 95 | ✅ **Safe** | No indicators. File appears clean. |
| ≥ 80 | 🟡 **Low** | Minor anomalies. Review flagged reasons. |
| ≥ 50 | 🟠 **Medium** | Multiple indicators. Inspect before use. |
| ≥ 20 | 🔴 **High** | Strong threat signals. Do not open without sandboxing. |
| < 20 | ☠️ **Critical** | Likely malicious. Quarantine immediately. |

---

## 📊 Model Performance

| Metric | Multi-Format Model | PE Malware Model |
|:---|:---:|:---:|
| Training Samples | 10,000 synthetic | 138,047 real PE headers |
| Test Accuracy | **99.80%** (Synthetic Multi-Format Proof-of-Concept) | **99.48%** |
| True Negative Rate | 99.93% | 99.61% |
| False Positive Rate | 0.07% | 0.39% |
| Algorithm | Random Forest (100 trees, max_depth=6) | Random Forest (tuned Random Forest) |
| Feature Space | 10 (normalized common vector) | 54 (PE header telemetry) |

---

## 🧪 Real-World Validation

TrustLens separates **model development evaluation** from **external validation**.
The multi-format Random Forest is trained and evaluated using its documented synthetic
feature-generation experiment. A separate validation layer can evaluate the same
10-feature model against an independently labelled real-world corpus.

This separation avoids data leakage and prevents synthetic benchmark performance from
being presented as real-world detection accuracy. The validation interface reports
accuracy, precision, recall, F1-score, ROC-AUC when both classes are present, a confusion
matrix, and file-level predictions. Any unsupported or PE samples are explicitly
reported as skipped rather than silently included.

Real-world results are corpus-specific and should be reported together with the source,
sample count, collection date, supported formats, and labelling methodology.

## 🔭 Future Scope

- [ ] **YARA Rule Integration** — Byte-pattern matching for signature-based augmentation alongside ML scores
- [ ] **REST API Service** — FastAPI endpoint for enterprise SIEM and SOAR platform integration
- [ ] **Real-World Corpus Training** — Fine-tune multi-format model on Contagio/VirusShare/EMBER datasets
- [ ] **VirusTotal API Integration** — Hash reputation lookup for real-time threat intelligence enrichment
- [ ] **Browser Extension** — Scan downloaded files directly from Chrome/Firefox before they are saved
- [ ] **LLM Explanation Layer** — LLM-generated threat narratives replacing rule-based reason text
- [ ] **CI/CD Security Gate** — GitHub Actions workflow scanning build artifacts at commit time
- [ ] **macOS/Linux Binary Support** — Mach-O and ELF binary header analysis plugins
- [ ] **Collaborative Reporting** — Multi-analyst shared scan history with team dashboard

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Fork → clone → branch
git checkout -b feat/your-feature-name

# Make changes, then verify
black src/ tests/
isort src/ tests/
PYTHONPATH=src pytest

# Commit using Conventional Commits
git commit -m "feat(analyzer): add YARA rule matching to ScriptAnalyzer"

# Push and open a Pull Request
git push origin feat/your-feature-name
```

---

## 📚 Research & Citation

If you use TrustLens AI in academic research, please cite:

```bibtex
@inproceedings{trustlens2026,
  title     = {TrustLens AI: Explainable Machine Learning and Modular Plugin
               Architecture for Multi-Format Static File Trust Analysis and
               MITRE ATT\&CK Mapping},
  author    = {[Authors]},
  booktitle = {Proceedings of IEEE International Conference on Cybersecurity},
  year      = {2026},
  institution = {Annamacharya Institute of Technology and Sciences
                 (Autonomous), Rajampet, India}
}
```

**Keywords:** Cybersecurity · Static Analysis · Random Forest · Plugin Architecture · Explainable AI · MITRE ATT&CK

---

## 📜 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built with ❤️ at **Annamacharya Institute of Technology and Sciences, Rajampet**

*B.Tech Computer Science & Engineering (Data Science) — Final Year Capstone 2026*

</div>
# Trust-Lens-Ai

## Original Work

The TrustLens AI implementation was developed by the project authors.

Original components include:

- plugin-based analyzer architecture
- file-format detection logic
- common feature normalization
- Trust Score and risk classification interface
- explanation and reason-generation logic
- MITRE ATT&CK association logic
- Streamlit dashboard
- PDF report generation
- synthetic multi-format evaluation data
- experimental scripts and project documentation

Third-party datasets, libraries, frameworks, publications, and
reference materials remain the property of their respective
owners/authors and are used according to their applicable terms.

## License

Copyright (c) 2026 TrustLens AI authors.

The original source code, project documentation, synthetic evaluation
data, and other materials created by the authors are released under
the MIT License, unless otherwise stated.

Third-party datasets, publications, trademarks, and other external
materials referenced by this project are NOT covered by this license
and remain subject to their respective rights and terms.

The Packt-distributed PE dataset used during the original experimental
evaluation is not included in this repository.

## Real-File Threat Prediction and Optional Hash Reputation

TrustLens supports static prediction on user-supplied real files using the existing PE and multi-format analyzers/models. Uploaded files are not executed. The application can also compute a SHA-256 digest locally and, only when `VIRUSTOTAL_API_KEY` is explicitly configured, query the provider for that hash. The file bytes are not uploaded by this feature. External reputation is supporting threat intelligence and must not be reported as TrustLens ML accuracy.

For final reporting, distinguish controlled synthetic holdout results from any external/real-file evaluation. Do not claim a universal real-world accuracy from a small or convenience corpus.


## External Real-World PDF Benchmark

TrustLens includes an optional reproducible evaluator for the CIC-Evasive-PDFMal2022 labelled PDF benchmark. The benchmark CSV is **not bundled**; obtain it from an authorized source and cite the dataset/paper. Run:

`python run_external_pdf_benchmark.py /path/to/PDFMalware2022.csv`

The benchmark result is reported separately from the existing 10-feature synthetic multi-format model because the corpus supplies PDF-specific extracted features rather than raw files. The current experiment used a stratified 70/30 split (random state 42) and an independent Random Forest benchmark classifier. **It must not be described as the accuracy of the existing TrustLens 10-feature model or as universal real-world accuracy.**

Current recorded external benchmark result from the supplied corpus: **97.61% accuracy**, malicious precision **99.34%**, malicious recall **99.70%**, malicious F1 **99.52%**, malicious ROC-AUC **99.99%**.
# Trust-Lens-Ai--Final
