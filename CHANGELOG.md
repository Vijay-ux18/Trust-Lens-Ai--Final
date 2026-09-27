# Changelog & Versioning Strategy

All notable changes to this project will be documented in this file.

This project adheres to **Semantic Versioning** (SemVer) (`MAJOR.MINOR.PATCH`):
- **MAJOR**: Incompatible API or structural changes.
- **MINOR**: Backward-compatible feature additions (e.g., adding a new plugin analyzer).
- **PATCH**: Backward-compatible bug fixes and style updates.

---

## [1.0.0] - 2026-08-02

### Added
- **Plugin Architecture**: Modular plugin interface (`BaseAnalyzer`) with dynamic routing for `pdf`, `office` (Word, Excel, PowerPoint), `executable`, `archive`, `script`, and `image` files.
- **Dual-Model Predictor Routing**: Auto-routing PE executables to a deep 54-feature Random Forest model, and documents/scripts to a calibrated 10-feature model.
- **Explainable Threat Diagnostics**: Natural-language checklist of triggered indicators for each scan.
- **MITRE ATT&CK Mapping Grid**: Mapped file anomalies to corresponding techniques in the MITRE ATT&CK Matrix.
- **PDF Security Report Compilation**: Automated ReportLab PDF generator creating high-quality, printable reports.
- **Multi-Format APK Support**: Extended archive scanning to support `.dex` bytecode and native `.so` executables inside Android packages.
- **Text & CSV Scan Audits**: Added plain text parsing capabilities for scanning shell scripts, base64 payloads, and command strings.
- **Macro-Enabled Office Support**: Added scanner triggers for `.docm`, `.xlsm`, and `.pptm` documents.
- **Test Suite**: 31 passed, 3 skipped unit and integration tests covering all critical execution boundaries.

### Fixed
- **Entropy False-Positives**: Calibrated document synthetic datasets so high compression entropy on PDFs/Word documents does not trigger pack/encryption warnings.
- **Decision Tree Shortcuts**: Refactored synthetic data generation to support independent multi-profile threats, eliminating single-feature overfitting.
- **Syntax Warnings**: Fixed backslash escape sequences in XML parsing regex inside `office.py`.
- **PyPDF2 Deprecations**: Migrated PDF parsing library to `pypdf` to prevent runtime warnings.

---

## [0.1.0] - 2026-08-01

### Added
- Initial project prototype with static PE executable model training and basic Streamlit UI.

## Real-World Prediction Hardening
- Added optional SHA-256 hash-only reputation lookup; file bytes are never uploaded.
- Corrected real-world validation confusion-matrix semantics for malicious-positive labels.
- Clarified that classifier probabilities are scores and are not calibrated universal real-world probabilities.
