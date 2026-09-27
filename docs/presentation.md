# TrustLens AI: Intelligent Multi-Format File Trust & Threat Analysis System
## Faculty-Level Project Presentation Slide Deck

---

### Slide 1: Title Slide
* **Slide Title**: TrustLens AI: Intelligent Multi-Format File Trust & Threat Analysis System
* **Subtitle**: A Static Plugin-Based Security Decision Support Framework with Explainable AI (XAI) and MITRE ATT&CK Mapping
* **Visual Layout**: Premium dark-blue gradient background with white typography. Left-aligned title text with project metadata on the right.
* **Content**:
  * **Academic Year**: 2026-2027
  * **Department**: Computer Science and Engineering (Data Science)
  * **Institution**: Annamacharya Institute of Technology and Sciences (Autonomous), Rajampet
  * **Project Associates**: `Shaik Sameera (23701A3276) (23701A3276)`
  * **Project Guide**: `Dr. P. Phanindra Kumar Reddy`
* **Speaker Notes**:
  > Good morning, esteemed members of the evaluation committee. Today, we present "TrustLens AI," an intelligent multi-format file trust and threat analysis system. Our project bridges the gap between machine learning classification and explainable cybersecurity. We statically analyze multiple file formats (including PDFs, Office documents, zip archives, scripts, and executables) to profile safety before files are loaded, providing an interactive, transparent decision-support system.

---

### Slide 2: Introduction & Motivation
* **Slide Title**: Introduction & Motivation
* **Visual Layout**: Two-column comparison layout with icons (Shield vs. Bug).
* **Content**:
  * **The Threat Landscape**: Endpoint environments receive diverse file types (PDF, Office, scripts, executables) from untrusted web downloads and email attachments.
  * **Zero-Execution Static Scan**: Examines file contents without executing the uploaded file, reducing the risk of triggering malicious code during analysis.
  * **Beyond Binary Scans**: Threats are no longer limited to PE binaries; malware dropper stubs utilize hidden scripts, document macros, and archive stubs.
  * **The Need for Transparency**: Traditional antivirus tools act as black boxes, blocking files without explaining the risk. TrustLens AI provides clear explanations.
* **Speaker Notes**:
  > Today's endpoints receive multiple file types. Attackers no longer rely solely on executables; they hide droppers inside PDF javascript, Word macros, and encrypted script blocks. Traditional security systems block these files as black boxes. TrustLens AI addresses this by statically parsing file headers and structures across multiple formats, calculating a clear trust score without executing the file.

---

### Slide 3: Problem Definition
* **Slide Title**: Problem Definition
* **Visual Layout**: Highlighted central text block with warning indicators.
* **Content**:
  * **Multi-Format Threat Propagation**: Lack of a single platform that statically analyzes diverse extensions (PDF, Office, scripts, binaries).
  * **Signature Evasion**: Attackers wrap files in custom cryptors or password-protected archives to bypass basic antivirus hashes.
  * **Exploitation of Legitimate Software**: Users open documents containing active VBA macros or PDF javascript hooks, triggering remote connections.
  * **Double Extension Masquerading**: Executables masquerading under non-executable extensions (e.g. `document.txt.exe` or `invoice.pdf` holding MZ magic bytes).
* **Speaker Notes**:
  > The problem definition lies in endpoint defense gaps. We face signature evasion where malware hides in archives, exploitation of document macros, and masquerading techniques (where executables disguise themselves with PDF or text extensions). We aim to build a unified system that parses these formats, extracts structural parameters, and profiles safety.

---

### Slide 4: Project Objectives
* **Slide Title**: Project Objectives
* **Visual Layout**: 4-quadrant layout with checkmarks.
* **Content**:
  * **Modular Plugin Architecture**: Design distinct analyzers for PDF, Word, Excel, PPT, Zip/Rar, scripts, executables, and image metadata.
  * **Common Vector Normalization**: Map diverse file features to a uniform 10-Dimensional Common Feature Vector.
  * **Ensemble Classification**: Train an optimized Random Forest model to predict risk rates with >95% accuracy.
  * **Explainable AI (XAI)**: Generate clear reasons explaining risk scores.
  * **MITRE ATT&CK Analysis**: Map selected static structural indicators to potential MITRE ATT&CK® associations using heuristic contextual rules.
* **Speaker Notes**:
  > Our primary objectives are: Establish a modular plugin architecture to analyze multiple formats; normalize diverse metadata to a uniform 10-Dimensional Common Feature Vector; train an ensemble Random Forest model; and provide plain-English explanations with heuristic contextual associations to MITRE ATT&CK®.

---

### Slide 5: Proposed System Architecture
* **Slide Title**: Proposed System Architecture
* **Visual Layout**: High-level block diagram representing data flow from upload to output.
* **Content**:
  * **Ingestion**: Upload files (PDF, Office, Zip, Script, Binary, Image).
  * **Plugin Selection**: Analyzer registry selects the matching parser at runtime.
  * **Normalization**: Maps format-specific features to the 10-Dimensional Common Feature Vector.
  * **Inference**: Predicts Trust Score and Risk Category using the serialized Random Forest pipeline.
  * **Presentation**: Displays score cards, dynamic monospace reports, and MITRE mapping details.
* **Speaker Notes**:
  > This block diagram outlines our system architecture. A user uploads any file type. The plugin registry selects the corresponding analyzer at runtime. Features are extracted and normalized to our 10-Dimensional Common Feature Vector. The inference module standardizes the vector and runs the Random Forest model to predict the Trust Score and Risk Category.

---

### Slide 6: Modular Plugin Analyzers
* **Slide Title**: Modular Plugin Analyzers
* **Visual Layout**: Grid of format icons representing registered plugins.
* **Content**:
  * **PDFAnalyzer**: Pages, hyperlinks, active JS streams, encryption flags.
  * **OfficeAnalyzers (Doc/Excel/PPT)**: VBA macros (`vbaProject.bin`), links count, embedded OLE objects, formulas, and media streams.
  * **ExecutableAnalyzer**: COFF optional headers, Import Address Tables, and section entropy.
  * **ArchiveAnalyzer**: Files counts, password protection, and nested executables.
  * **ScriptAnalyzer**: Command keywords, hex/base64 obfuscation scoring.
  * **ImageAnalyzer**: Width, height, color modes, and EXIF metadata density.
* **Speaker Notes**:
  > Our plugin architecture contains dedicated scanners. The PDF plugin checks for javascript and links; the Office plugin checks for macros and hidden worksheets; the script analyzer checks for base64 blocks and shell executables; and the executable plugin parses PE headers. New plugins can be added without modifying the core pipeline.

---

### Slide 7: Feature Normalization & 10-D Mapping
* **Slide Title**: Feature Normalization & 10-D Mapping
* **Visual Layout**: Mapping flow showing format-specific details merging to a common vector.
* **Content**:
  * **Challenge**: Different files contain different features (e.g. page count vs. PE checksum).
  * **Solution**: Normalize diverse features to a uniform 10-Dimensional Vector:
    1. `file_size_kb` | 2. `entropy` | 3. `has_executable_code`
    4. `has_obfuscation` | 5. `has_network_indicators` | 6. `has_macros_or_scripts`
    7. `is_encrypted_or_packed` | 8. `has_masquerading` | 9. `metadata_density`
    10. `suspicious_indicators_count`
* **Speaker Notes**:
  > Since a PDF doesn't have a PE checksum and an executable doesn't have pages, we normalize all extracted metadata into a uniform 10-Dimensional Common Feature Vector. This allows a single, optimized machine learning model to evaluate any format.

---

### Slide 8: Machine Learning Training Pipeline
* **Slide Title**: Machine Learning Training Pipeline
* **Visual Layout**: Step-by-step progress chart.
* **Content**:
  * **Dataset Ingestion**: Generated a training dataset of 10,000 samples representing diverse risk profiles (Safe, Low, Medium, High, Critical).
  * **Preprocessing**: StandardScaler normalizes feature ranges.
  * **Stratified Split**: 70:30 Train-Test split maintains profile proportions.
  * **Model Fit**: Scikit-Learn RandomForestClassifier trained on normalized feature vectors.
  * **Asset Serialization**: Saves `multiformat_model.joblib` and `multiformat_preprocessor.joblib`.
* **Speaker Notes**:
  > Our training pipeline processes a multi-format dataset of 10,000 records. Features are scaled using a StandardScaler. We split the data using a 70:30 stratified split and train a Random Forest classifier. The final estimator and scaler are serialized to joblib assets.

---

### Slide 9: Model Performance & Tuning
* **Slide Title**: Model Performance & Tuning (Random Forest)
* **Visual Layout**: Large data table comparing model metrics.
* **Content**:
  * **PE Model Holdout Accuracy**: **99.48%** on the independent 41,415-sample holdout.
  * **Multi-Format Synthetic Holdout Accuracy**: **99.80%** (proof-of-concept benchmark).
  * **External Validation**: The same multi-format model now has a separate real-world validation workflow; results are calculated only from an actually supplied labelled corpus.
  * **Feature Importances (Multi-Format)**:
    * `suspicious_indicators_count`: **0.38**
    * `metadata_density`: **0.25**
    * `has_obfuscation`: **0.13**
    * `has_executable_code`: **0.12**
  * **Evaluation Integrity**: Synthetic benchmark and external real-world validation are reported separately.
* **Speaker Notes**:
  > The PE model has a 99.48% holdout result, while the 10-feature multi-format model has a 99.80% synthetic proof-of-concept result. We do not present the synthetic score as universal real-world accuracy. The project includes a separate static real-world validation workflow that calculates accuracy, precision, recall, F1-score and ROC-AUC from an independently labelled corpus.

---

### Slide 10: Risk Categorization & Decision Logic
* **Slide Title**: Risk Categorization & Decision Logic
* **Visual Layout**: Color-coded risk ladder.
* **Content**:
  * **Safe (Green)**: Trust Score $\ge$ 95%. No significant static indicators detected; further organizational security controls are recommended.
  * **Low (Blue)**: Trust Score $\ge$ 80%. Normal files with minor metadata.
  * **Medium (Orange)**: Trust Score $\ge$ 50%. Legacy formats or missing mitigations.
  * **High (Red)**: Trust Score $\ge$ 20%. Active obfuscation or macros.
  * **Critical (Dark Red)**: Trust Score < 20%. Active bypass / spoofing.
* **Speaker Notes**:
  > The predictor maps trust probabilities to five standardized risk categories: Safe, Low, Medium, High, and Critical. This gives users immediate, actionable indicators.

---

### Slide 11: Confusion Matrix Analysis
* **Slide Title**: Confusion Matrix Analysis (41,415 Test Partition)
* **Visual Layout**: 2x2 grid representing predicted vs. actual values.
* **Content**:
  * **Confusion Matrix Data**:
    * **True Negative (TN)**: **28,906** (Malicious correctly blocked)
    * **True Positive (TP)**: **12,295** (Benign correctly allowed)
    * **False Positive (FP)**: **112** (Malicious predicted benign - Evasion Risk)
    * **False Negative (FN)**: **102** (Benign predicted malicious - False Alarm)
  * **Balanced Errors**: Equal distribution of errors demonstrates model stability.
* **Speaker Notes**:
  > Evaluating the model on the test partition of 41,415 samples: 28,906 clean files were correctly allowed, and 12,295 threat profiles were correctly blocked. The classifier had 112 false positives and 102 false negatives, confirming stable classification bounds.

---

### Slide 12: Rule-Based Explanations Engine
* **Slide Title**: Rule-Based Explanations Engine
* **Visual Layout**: Checklist displaying clean alert criteria.
* **Content**:
  * **JavaScript Detected**: Triggered if active JS hooks reside inside PDF catalogs.
  * **Active Macros**: Triggered if VBA binary project files are resolved.
  * **Code Obfuscation**: Flagged if script obfuscation score > 3 or entropy > 7.2.
  * **Binary Masquerading**: Triggered if MZ magic bytes are detected inside non-executable extensions.
* **Speaker Notes**:
  > To provide clear context, our explanations engine checks thresholds on the common vector. It flags active macros in Office documents, Javascript blocks in PDFs, obfuscation in scripts, and binary masquerading, outputting a clear reasons checklist.

---

### Slide 13: MITRE ATT&CK Mapping
* **Slide Title**: MITRE ATT&CK Mapping
* **Visual Layout**: Structured table matching behaviors to tactics.
* **Content**:
  * **Extension Masquerading** -> *Defense Evasion: Masquerading (potential association (heuristic/contextual))*
  * **VBA Droppers** -> *Execution: User Execution - Malicious File (T1204.002)*
  * **High File Entropy** -> *Defense Evasion: Software Packing (T1027.002)*
  * **Hidden Dynamic Imports** -> *Defense Evasion: Obfuscated Files (T1027)*
  * **Missing DEP / ASLR** -> *Potential Execution: Exploitation for Privilege Escalation (potential association (heuristic/contextual)) association*
* **Speaker Notes**:
  > Handled anomalies are mapped to the MITRE ATT&CK database. Masquerading maps to potential association (heuristic/contextual), document droppers to T1204.002, and packed files to T1027.002. This provides security teams with immediate tactical context.

---

### Slide 14: Presentation Layer: Web Interface
* **Slide Title**: Presentation Layer: Web Interface
* **Visual Layout**: Key highlights of the Streamlit dashboard layout.
* **Content**:
  * **Landing Page (`app.py`)**: General static scanning principles.
  * **Scanner (`01_Upload_Predict.py`)**: Drag-and-drop file upload. Displays trust gauge, risk category, reasons checklist, and PDF download button.
  * **Dashboard (`02_Dashboard.py`)**: Scan history logs, safe/suspicious counts, and risk distribution chart.
  * **MITRE Matrix (`03_MITRE_ATTACK.py`)**: Maps selected static structural indicators to potential MITRE ATT&CK® associations using heuristic contextual rules.
* **Speaker Notes**:
  > The frontend is built with Streamlit. The scanner page includes our trust gauge, risk category card, and reasons checklist. The dashboard logs history, and the MITRE page correlates anomalies with attacker tactics.

---

### Slide 15: System Testing & QA
* **Slide Title**: System Testing & Quality Assurance
* **Visual Layout**: Test suite pass metrics.
* **Content**:
  * **Unit Tests**: Verifies feature extraction across PDF, Doc, Excel, PPT, Archives, Scripts, and Images.
  * **Integration Tests**: Confirms normalization pipelines and scaler transformations.
  * **test/mock scenario only**: Falls back to heuristic diagnostics if model files are missing.
  * **Pytest Runner**: Confirms **Pytest verification: 31 passed, 3 skipped.**
* **Speaker Notes**:
  > Our current test suite contains 31 passing tests and 3 skipped tests written in `pytest`. We cover unit tests for each analyzer, integration tests for the normalizer, and error fallbacks.

---

### Slide 16: Key Architecture Improvements
* **Slide Title**: Key Architecture Improvements
* **Visual Layout**: Comparison cards focusing on security fixes.
* **Content**:
  * **Dynamic Path Portability**: Resolved hardcoded base path issues in `save_model.py`. System dynamically detects workspace roots, enabling execution on any environment.
  * **Joblib Deserialization Boundary**: Validates absolute paths to block arbitrary code loading during model deserialization.
  * **Network Resilience**: Wrap pipeline data downloads in try-except blocks to fallback to local files if Dropbox/GitHub is offline.
* **Speaker Notes**:
  > We implemented key architectural improvements: Dynamic path validation resolves workspace roots at runtime, ensuring portability; joblib load boundaries block path traversal; and try-except blocks prevent crashes during network timeouts.

---

### Slide 17: Future Work & Enhancements
* **Slide Title**: Future Work & Enhancements
* **Visual Layout**: Future Roadmap list.
* **Content**:
  * **SHAP Explainability**: Integrate SHAP value charts inside the Advanced technical expander.
  * **Cross-Platform Parsers**: Extend the executable analyzer to support Linux ELF and macOS Mach-O binaries.
  * **Sandbox API Integrations**: Automatically route high-risk files to virtualized sandboxes for behavioral analysis.
* **Speaker Notes**:
  > Future work includes integrating SHAP value explainability, adding Linux ELF and macOS Mach-O analyzers, and linking the portal to dynamic sandboxes for hybrid analysis.

---

### Slide 18: Client PDF Report Generation
* **Slide Title**: Client PDF Report Generation
* **Visual Layout**: PDF report outline visual.
* **Content**:
  * **ReportLab Integration**: Compiles custom, publication-grade PDF summaries.
  * **Contained Information**:
    * Target filename, type, size, and timestamp.
    * Color-coded Risk Assessment banner.
    * Matplotlib Trust Score Donut Chart.
    * Plain-English Reasons Checklist.
* **Speaker Notes**:
  > Users can download a clean PDF report. Built with ReportLab, it includes file details, a color-coded risk banner, a trust score donut chart, and a reasons checklist, omitting raw developer metadata.

---

### Slide 19: Conclusion
* **Slide Title**: Conclusion
* **Visual Layout**: Summary cards with key achievements.
* **Content**:
  * **Summary**: TrustLens AI delivers a rapid, zero-execution multi-format file analyzer, with the core PE model achieving **99.48% ML accuracy**.
  * **Modularity**: Plugin structure enables adding new analyzers without changing the core predictor.
  * **Usability**: Interactive web dashboard, risk profiling cards, and clear checklist reports.
* **Speaker Notes**:
  > In conclusion, TrustLens AI delivers a modular, multi-format trust analysis platform. By shifting from PE-only classification to plugin analyzers and common vector normalizations, we provide a robust endpoint defense tool where the PE analyzer achieves 99.48% accuracy.

---

### Slide 20: Faculty Review Q&A
* **Slide Title**: Faculty Review Q&A
* **Visual Layout**: List of anticipated questions.
* **Content**:
  * **Anticipated Questions**:
    * *Q1: How do you normalize features from different formats into a single vector?*
    * *Q2: How does the system handle encrypted files?*
    * *Q3: What are the security advantages of dynamic path validation in production?*
* **Speaker Notes**:
  > We have listed anticipated questions focusing on feature normalization, encrypted file handling, and dynamic path validation. Thank you, and we welcome your questions.

---

## TRUSTLENS AI - INTERACTIVE DEMO SCRIPT

### 1. Ingestion of a Benign PDF
- **Presenter Action**: Open browser to `http://localhost:8501`. On the Scanner page, drag and drop `report.pdf`.
- **Narrative**: *"We upload a standard PDF. The system matches it to the PDFAnalyzer, counts pages, and extracts metadata. It scores a 100% Trust Score, returning a Safe Risk level. The Reasons Checklist shows no anomalies."*

### 2. Ingestion of a Phishing PDF with JavaScript
- **Presenter Action**: Drag and drop a PDF file designed with active script parameters (simulated payload).
- **Narrative**: *"Next, we upload a phishing PDF. The analyzer detects dynamic JavaScript stubs and embedded links. The model evaluates these features, rendering a 15% Trust Score and a Critical Risk banner. The reasons checklist flags: JavaScript detected, Contains 18 embedded hyperlinks, and Unknown author."*

### 3. Archive with Executable payloads
- **Presenter Action**: Drag and drop a ZIP archive containing a nested `.exe` payload.
- **Narrative**: *"When we scan a ZIP archive, the ArchiveAnalyzer extracts the files listing, identifying nested executables. The system maps this to the common vector, returning a High Risk rating."*

### 4. MITRE ATT&CK Correlation
- **Presenter Action**: Click **MITRE ATT&CK** page on the sidebar.
- **Narrative**: *"The detected behaviors are mapped to the MITRE framework. Masquerading maps to potential association (heuristic/contextual) and nested droppers map to T1204.002, providing analysts with clear tactical context."*

### 5. Report Compilation
- **Presenter Action**: Return to the scanner, click **Download PDF Report** and open the generated PDF.
- **Narrative**: *"We download the generated report, showing file parameters, the risk banner, a trust donut chart, and the reasons checklist."*

---

## ANTICIPATED FACULTY VIVA-VOCE QUESTIONS & ANSWERS

#### Q1: How do you normalize features from different formats into a single common feature vector?
- **Answer**: Format-specific analyzers extract attributes unique to each file type. The normalization layer maps these attributes to standard, boolean or scaled metrics representing generalized security indicators (e.g. mapping PDF JavaScript counts or Office macro detections to the same `has_executable_code` field). This produces a uniform 10-dimensional vector suitable for standard machine learning classifiers.

#### Q2: How does the system handle encrypted archives or password-protected files?
- **Answer**: The system cannot parse encrypted payloads statically. The archive and document analyzers detect encryption headers (e.g., ZIP encryption flags) and set `is_encrypted_or_packed = 1.0` in the common vector. This alerts the user to run scans inside an isolated sandbox, maintaining transparent security posture.

#### Q3: What is the benefit of dynamic path validation in your code?
- **Answer**: Hardcoded project paths break code portability when run on new environments. Our dynamic path validation resolves the workspace root relative to the module file at runtime. This prevents permission errors on new developer, guide, or examiner machines while blocking directory traversal attacks during serialization.
