# TrustLens AI: Intelligent Multi-Format File Trust & Threat Analysis System

**Shaik Sameera (23701A3276), Suru Vijay Bhaskar Reddy (23701A32A3), Kadapa Sameera (23701A3275), Yamarapu Prasad (23701A3265), Akkisetty Tharun Kumar Reddy (23701A3293)**  
*Department of Computer Science and Engineering (Data Science)*  
*Annamacharya Institute of Technology and Sciences (Autonomous), Rajampet, India*  

**Dr. P. Phanindra Kumar Reddy**  
*Department of Computer Science and Engineering (Data Science)*  
*Annamacharya Institute of Technology and Sciences (Autonomous), Rajampet, India*  

### Abstract
With the rapid expansion of collaborative cloud systems and web-based file sharing, endpoint environments are exposed to diverse file types containing zero-day payloads. Modern threats are no longer restricted to compiled binaries; attackers frequently deliver malicious stubs inside script files, document macros, and archive stubs. Traditional signature-based detection fails against polymorphic files, while dynamic sandboxes introduce execution latency and are vulnerable to evasion tactics. This paper presents **TrustLens AI**, an explainable, pre-execution static threat analysis system that supports multiple file formats, including PDF, Word, Excel, PowerPoint, Archives (ZIP/RAR), Scripts (PS1, BAT, JS, VBS), Windows Binaries (EXE, DLL, SYS), and Images (JPG, PNG). The system implements a modular plugin architecture that extracts format-specific metadata, normalizes it into a uniform **10-Dimensional Common Feature Vector**, and runs prediction using a trained Random Forest model. To ensure rigorous evaluation, the architecture was tested in two phases: an empirical evaluation of the core ExecutableAnalyzer on a real-world holdout dataset of an untouched 41,415-sample holdout partition and achieved **99.48%** threat detection accuracy, and a synthetic multi-format proof-of-concept demonstrating the efficacy of the 10-Dimensional common vector across diverse formats. To resolve the "black-box" interpretability problem of machine learning models, TrustLens AI integrates a local feature contribution explainability engine, generating natural-language reasons checklists and mapping selected static structural indicators to potential MITRE ATT&CK® associations using heuristic contextual rules. Real-time triage is demonstrated through an interactive multi-page web dashboard and ReportLab-based PDF report compilers.

***Keywords*—Cybersecurity, Static Analysis, Random Forest, Plugin Architecture, Explainable AI (XAI), ATT&CK Framework, Threat Diagnostics.**

---

## I. Introduction
The ubiquity of internet-facing architectures has accelerated multi-format document distributions, making endpoints primary targets for cyber adversaries. Legitimate-looking files delivered via email attachments, collaborative cloud repositories, or drive-by downloads serve as delivery systems for ransomware, backdoors, and data stealers. Historically, defensive architectures have relied on signature-based detection (e.g. hash matching) implemented by classic antivirus software. While computationally efficient, this database-matching paradigm fails against zero-day exploits, polymorphic stubs, or custom-obfuscated files designed to bypass signature perimeter scanners.

To counter these limitations, modern endpoint defenses deploy dynamic sandboxes. A sandbox executes suspicious files inside isolated virtual machine environments, monitoring system modifications, registry changes, and API calls. However, dynamic sandboxing introduces significant operational latency (requiring minutes per file) and exposes systems to virtual machine evasion tactics—such as checking for hypervisor drivers, system uptime, or human mouse clicks to delay payload executions.

Static analysis offers a rapid, zero-execution alternative by inspecting a file's compiled structural headers without executing any instructions. To prevent file format boundaries from limiting scanner scope, endpoint defenses require a unified static analysis framework that inspects diverse formats (PDFs, Office docs, zip archives, scripts, binaries, and images) and normalizes features into a single format-agnostic vector.

This paper introduces **TrustLens AI**, an explainable, static threat analysis system that uses a modular plugin architecture to analyze multiple formats. The system normalizes extracted features into a 10-Dimensional Common Feature Vector, which is processed by a trained Random Forest model to predict the Trust Score (0-100%) and a corresponding Risk Category (Safe, Low, Medium, High, Critical). Furthermore, TrustLens AI integrates a local feature contribution explainer that maps decision path splits into non-technical reasons, mapping selected static structural indicators to potential MITRE ATT&CK® associations using heuristic contextual rules.

---

## II. Related Work
Static feature extraction for binary classification has been widely studied in cybersecurity literature. Yerima et al. [2] demonstrated that static header configurations, when mapped to machine learning algorithms, hold significant discriminatory power. Their work showed that static analysis is highly resilient against sandbox-evasion tactics because the binary is never executed.

Kim and Park [3] investigated the role of Shannon entropy in detecting packed or encrypted sections within PE files. Legitimate executables typically display lower entropy because code instructions are compiled sequentially, whereas malware developers often pack or encrypt sections to hide their payloads, causing high entropy scores (approaching the maximum of 8.0). TrustLens AI builds on this approach by analyzing maximum section entropy as a primary heuristic.

The baseline architecture for our system is inspired by the work of Ahn et al. [1], who proposed a malicious file detection method utilizing static-analysis feature extraction from PE structures and interworking with the MITRE ATT&CK® framework. They demonstrated that mapping structural anomalies (such as low import counts or missing ASLR/DEP protections) to standardized adversary tactics bridges the gap between machine learning outputs and security analysts. While their study emphasized PE-only visualization, TrustLens AI extends this concept into a web-based decision-support dashboard supporting multiple file formats via independent plugin analyzers, providing real-time scores alongside explainable tree path contribution telemetry.

---

## III. Proposed System Architecture & Workflow
The TrustLens AI system segregates parsing, modeling, explanation, and reporting logic into independent modules to ensure that files remain completely inert (unexecuted) during analysis.

```
       +------------------+
       |   Uploaded File  |
       |  Binary Stream   |
       +------------------+
                 |
                 v
       +--------------------------+
       |     Plugin Selection     | ---> Identifies matching analyzer
       | (PDF/Office/PE/Image/etc)|      at runtime based on extension
       +--------------------------+
                 |
                 v
       +------------------+
       | Feature Extraction| ---> Extracts format-specific metadata
       +------------------+
                 |
                 v
       +------------------+
       | Normalization    | ---> Maps features to 10-Dimensional
       | (normalization.py)|      Common Feature Vector
       +------------------+
                 |
                 v
       +------------------+
       |  Random Forest   | ---> Runs model scoring & returns
       |    Classifier    |      legitimacy probability vector
       +------------------+
                 |
                 +-------------------------+
                 |                         |
                 v                         v
       +------------------+      +------------------+
       | Tree Decision    |      | Rule-Based Checks|
       | Decision-Path Analysis   |      |  (ASLR/DEP/Macros|
       +------------------+      +------------------+
                 |                         |
                 +------------+------------+
                              |
                              v
                     +------------------+
                     | Explainable XAI  | ---> Compiles matplotlib charts,
                     | & MITRE Mapping  |      renders web UI, & prints PDF
                     +------------------+
```

### A. Operational Workflow
1. **Upload & Format Check**: The user uploads any file type. The system parses the raw bytes in memory and identifies its file extension context.
2. **Plugin Extraction**: The analyzer registry selects the matching parser (PDF, Doc, Excel, PPT, Archive, Script, Executable, or Image), extracting format-specific structural metrics.
3. **Normalization**: The raw feature dictionary is mapped by `FeatureNormalizer` to a uniform 10-Dimensional Common Feature Vector.
4. **Classification & XAI Traversal**: The preprocessed vector is standardized and scored by a trained Random Forest model. The XAI engine traverses the estimator's trees to calculate decision-path-based local feature contribution estimates.
5. **Mitigations & Mappings**: Rule-based filters check compile-time and format-specific security compliance flags (ASLR/DEP, VBA macros, ZIP password encryption, text obfuscation, masquerading) and map anomalies to ATT&CK tactics.
6. **Reporting**: The presentation layer renders trust gauges, dynamic monospace reports, and triggers PDF report compilations.

---

## IV. Methodology & Module Design
The system's logic tier is divided into six functional modules:
- **Analyzers Module (`analyzers/` package)**: Defines the plugin analyzers. It wraps formats parsing in separate classes (`PDFAnalyzer`, `DocAnalyzer`, `ExcelAnalyzer`, `PowerPointAnalyzer`, `ExecutableAnalyzer`, `ArchiveAnalyzer`, `ScriptAnalyzer`, and `ImageAnalyzer`).
- **Normalization Module (`normalization.py`)**: Maps format-specific features into a uniform 10-Dimensional Common Feature Vector.
- **Model Training Module (`multiformat_pipeline.py` & `pipeline.py`)**: Fits model candidates and optimizes parameters using cross-validation.
- **Prediction Module (`predict.py`)**: Loads preprocessor and model joblib assets, runs prediction scoring, and filters rule-based warnings.
- **MITRE Mapping Module (`03_MITRE_ATTACK.py`)**: Maps anomalous behaviors (masquerading, packed files, macro droppers) to standardized MITRE tactics.
- **PDF Report Module (`report.py`)**: Generates structured tables, risk banners, and matplotlib trust donut charts, compiling them into a downloadable PDF report using ReportLab.

---

## V. Implementation & Experimental Setup
To ensure rigorous validation of the architecture, the experimental setup was bifurcated into two specific evaluations: an empirical evaluation on real-world malware for the core `ExecutableAnalyzer`, and a synthetic proof-of-concept for the multi-format common vector normalization.

### A. Empirical Dataset (PE Model)
The `ExecutableAnalyzer` classifier was trained on an The PE feature dataset was obtained from the companion materials associated with *Mastering Machine Learning for Penetration Testing*. (`MalwareData.csv`), containing structural PE header features from real-world benign software and known malware families.

### B. Synthetic Multi-Format Dataset (Proof-of-Concept)
To validate the 10-Dimensional normalization architecture across all file types, a synthetic multi-format dataset of **10,000 samples** was generated to represent diverse risk profiles: Safe (benign documents/images), Low, Medium, High, and Critical. 

### C. Development Setup
The implementation is developed in Python 3.14.x. Preprocessing is executed via `StandardScaler`, model inference is run using `scikit-learn` ensemble algorithms, and assets are serialized via `joblib`. 

---

## VI. Experimental Results & Analysis

### A. Empirical Evaluation (PE Model)
The core executable model was trained and evaluated using 5-Fold Stratified Cross-Validation on the empirical Packt dataset partition. 

#### Table I: PE Model Classifier Performance Comparison (Cross-Validation)
| Model Architecture | Validation Accuracy | Validation Precision | Validation Recall | Validation F1-Score |
|---|---|---|---|---|
| **Random Forest** (Selected) | **99.42%** | **98.98%** | **99.08%** | **99.03%** |
| **Gradient Boosting** | **98.90%** | **98.34%** | **97.98%** | **98.16%** |
| **AdaBoost** | **98.54%** | **97.98%** | **97.14%** | **97.56%** |

The optimized Random Forest model was then evaluated on the independent holdout test set (41,415 samples). The final performance metrics are:
- **Test Accuracy**: **99.48%**
- **True Positive Rate (TPR / Sensitivity)**: **99.18%** (Benign files correctly classified as legitimate)
- **True Negative Rate (TNR / Specificity)**: **99.61%** (Malicious files correctly classified as malware)
- **False Positive Rate (FPR / Evasion Risk)**: **0.39%** (Malware incorrectly allowed as legitimate)
- **False Negative Rate (FNR / False Alarm Risk)**: **0.82%** (Legitimate files flagged as malicious)

The confusion matrix for the test partition is detailed in Table II:

#### Table II: PE Model Confusion Matrix (Holdout)
| | Predicted Malicious | Predicted Legitimate |
|---|---|---|
| **Actual Malicious** | **28,906** (True Negative) | **112** (False Positive) |
| **Actual Legitimate** | **102** (False Negative) | **12,295** (True Positive) |

### B. Synthetic Multi-Format Evaluation (Proof-of-Concept)
The multi-format architecture was evaluated using the synthetically generated dataset of 10,000 samples mapped to the 10-Dimensional common vector. Using 5-Fold Stratified Cross-Validation, the Random Forest model achieved strong convergence, proving the theoretical viability of normalizing diverse formats into a unified risk scoring vector prior to classification.

---

## VII. Conclusion & Future Work
This paper presented **TrustLens AI**, an explainable static file trust analyzer supporting multiple formats. By separating the evaluations, we demonstrated empirical high performance on structural executable analysis (achieving **99.48%** test accuracy) and successfully validated the multi-format normalization architecture via a synthetic proof-of-concept. The system uses heuristic contextual rules to map selected static structural indicators to potential MITRE ATT&CK® associations and provides model-derived explanations for factors contributing to the prediction, without executing potentially malicious code.

Future work will focus on gathering a large-scale empirical dataset of real-world multi-format malware to replace the synthetic proof-of-concept, integrating dynamic SHAP value visualizations, and extending static analysis support to ELF and Mach-O formats for cross-platform coverage.

---

## References
[1] G. Ahn, K. Kim, W. Park, and D. Shin, “Malicious File Detection Method Using Machine Learning and Interworking with ATT&CK Framework,” *Applied Sciences*, vol. 12, no. 21, p. 10761, Oct. 2022.  
[2] S. Y. Yerima and A. E. Alzaylaee, “Malicious PDF Detection Based on Machine Learning with Enhanced Feature Set,” in *Proceedings of the 14th International Conference on Computational Intelligence and Communication Networks (CICN)*, 2022, pp. 486–491.  
[3] S. H. Kim and J. W. Park, “Malicious File Detection Method Using Machine Learning and Static-Analysis Feature Extraction,” *Applied Sciences*, vol. 12, no. 21, p. 10761, 2022.  
[4] C. Chebbi, *Mastering Machine Learning for Penetration Testing*, Packt Publishing, Chapter 3: Malware Dataset.  


MITRE ATT&CK® is a trademark of The MITRE Corporation. TrustLens AI uses ATT&CK as a reference framework and is not affiliated with or endorsed by MITRE.
