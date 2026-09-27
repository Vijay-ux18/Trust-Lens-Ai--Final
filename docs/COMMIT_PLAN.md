# Git Commit History Plan

This document outlines a structured, 30-commit development history for TrustLens AI following the **Conventional Commits** specification. This provides the project team with a clean commits sequence to simulate or apply when initializing the repository on GitHub.

---

## Commit Log Sequence

1. `chore: initialize repository structure and build configurations`
   - Setup project tree, `pyproject.toml`, target `.python-version`, and `.env.example`.
2. `docs: add initial project abstract and overview documentation`
   - Add draft project specifications, academic details, and general architecture summaries.
3. `chore: define production requirements and locking versions`
   - Pin scikit-learn, streamlit, PyPDF2, pefile, numpy, pandas, and reportlab in `requirements.txt`.
4. `feat(analyzer): implement BaseAnalyzer abstract base class`
   - Define plugin architecture standard interfaces and exception boundaries.
5. `feat(analyzer): implement PDFAnalyzer plugin for static PDF telemetry`
   - Extract page counts, active JavaScript calls, embedded external URIs, and encryption parameters.
6. `feat(analyzer): implement Office document analyzers for doc, xls, ppt`
   - Parse OLE streams, active VBA macros, and hidden sheet counts.
7. `feat(analyzer): implement ExecutableAnalyzer for PE binaries`
   - Extract 54 essential PE header attributes using `pefile`.
8. `feat(analyzer): implement ArchiveAnalyzer for ZIP and RAR parsing`
   - Detect nested archive chains, embedded executable payloads, and password encryption flags.
9. `feat(analyzer): implement ScriptAnalyzer for scripts and batch files`
   - Detect PowerShell/JS dropper patterns, shell execution keywords, and base64 payloads.
10. `feat(analyzer): implement ImageAnalyzer for EXIF metadata validation`
    - Extract image dimensions, check metadata presence, and calculate byte entropy.
11. `feat(analyzer): implement FeatureNormalizer interface`
    - Map diverse format-specific metrics into a uniform 10-Dimensional Common Feature Vector.
12. `feat(pipeline): create static PE malware dataset parser and preprocessor`
    - Parse PE headers CSV, format missing values, and construct preprocessing pipelines.
13. `feat(pipeline): implement PE classifier training and validation script`
    - Train Random Forest classifier and output metrics evaluation.
14. `feat(predict): construct core TrustLensPredictor engine`
    - Manage asset loads, dynamic analyzer dispatching, and fallback scoring.
15. `feat(explanation): create XAI local feature contribution explainer`
    - Generate human-readable reason checklists and recommendations from feature splits.
16. `feat(report): construct PDF report generator service`
    - Build ReportLab compile engine generating printable security review certificates.
17. `feat(ui): design main Streamlit home landing page`
    - Implement navigation sidebar, overview card grids, and status headers.
18. `feat(ui): build Streamlit file upload and predict page`
    - Implement drop-zone, real-time risk gauges, checklists, and PDF report triggers.
19. `feat(ui): build Streamlit dashboard and scan history page`
    - Integrate session scan logs, cumulative metrics, and interactive charts.
20. `feat(ui): build Streamlit MITRE ATT&CK mapping grid`
    - Display ATT&CK mapping table highlighting triggered threat techniques.
21. `test: add plugin analyzer unit tests`
    - Validate PDF, Word, script, PE, and image scanning logic.
22. `test: add predictor pipeline integration tests`
    - Validate end-to-end scoring, normalization mapping, and fallback paths.
23. `fix(pipeline): resolve benign document entropy false-positives`
    - Update synthetic training dataset profiles to handle normal compressed document entropy.
24. `fix(pipeline): eliminate model shortcuts in synthetic data generator`
    - Refactor dataset simulation to generate independent multi-profile threat vectors.
25. `feat(analyzer): extend ArchiveAnalyzer to support Android APK structures`
    - Add `.dex` bytecode and `.so` library checks to executable content scanner.
26. `feat(analyzer): extend ScriptAnalyzer to audit plain text and CSV files`
    - Map text and CSV extensions to verify embedded commands and URL references.
27. `feat(analyzer): extend Office analyzers to support macro-enabled extensions`
    - Register `.docm`, `.xlsm`, and `.pptm` documents under format-specific analyzers.
28. `fix(metadata): migrate PDF parser library from PyPDF2 to pypdf`
    - Resolve deprecation warnings and stabilize PDF metadata extraction.
29. `style: format and clean source code to meet PEP 8 standards`
    - Apply `black` formatting, sort imports with `isort`, and remove dead variables.
30. `docs: finalize professional README and repository files for release`
    - Complete setup instructions, contributing rules, changelog, and license files.
