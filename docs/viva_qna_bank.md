# TrustLens AI: Comprehensive Faculty & External Examiner Viva-Voce Q&A Bank
This document compiles a structured database of **200 viva-voce questions and answers** to prepare candidates for the B.Tech project defense. The questions span basic, intermediate, and advanced categories across cybersecurity, machine learning, Python, Streamlit, project design, testing, and research methodologies.

## Table of Categories
- **Category A: Basic Cybersecurity & PE Structure (Q1–Q30)**
- **Category B: Basic to Intermediate Python & Streamlit (Q31–Q60)**
- **Category C: Intermediate Machine Learning & Preprocessing (Q61–Q90)**
- **Category D: Advanced Ensemble Algorithms & Optimization (Q91–Q120)**
- **Category E: Explainable AI (XAI) & Tree Traversal Math (Q121–Q145)**
- **Category F: MITRE ATT&CK & Cybersecurity Compliance (Q146–Q165)**
- **Category G: Project Design, Testing & QA (Q166–Q180)**
- **Category H: Guide & External Examiner Defense (Q181–Q200)**

---

### Category A: Basic Cybersecurity & PE Structure (Q1–Q30)

#### Q1: What is a Portable Executable (PE) file?
**Answer**: A PE file is a standard file format for executables, object code, and DLLs in 32-bit and 64-bit Windows operating systems. It contains headers and sections that describe how the OS loader should map the file into virtual memory.

#### Q2: What are the two major header groups in a PE file?
**Answer**: The COFF (Common Object File Format) Header and the Optional Header.

#### Q3: What is the DOS stub and why is it present in PE headers?
**Answer**: The DOS stub is a legacy compatibility block at the very beginning of a PE file that prints 'This program cannot be run in DOS mode' if executed in an MS-DOS environment.

#### Q4: What are the magic bytes at the start of a Windows PE file?
**Answer**: The signature 'MZ' (hex 0x5A4D), which stands for Mark Zbikowski, the designer of the MS-DOS executable format.

#### Q5: What does the COFF header 'Characteristics' field represent?
**Answer**: It is a bitmask representing flags such as whether the file is an executable image, a DLL, a system file, or if debug symbols have been stripped.

#### Q6: Explain the purpose of the 'SizeOfOptionalHeader' field in the COFF header.
**Answer**: It specifies the size of the Optional Header, allowing loaders to correctly parse section headers that immediately follow the Optional Header, even if the Optional Header size varies.

#### Q7: What is the Image Base in the PE Optional Header?
**Answer**: The Image Base is the preferred virtual memory address where the operating system loader maps the executable when launching the process.

#### Q8: Explain Address Space Layout Randomization (ASLR).
**Answer**: ASLR is a defense mitigation that randomizes the virtual address space locations of key areas (such as base executable, stack, heap, and libraries) to prevent Return-Oriented Programming (ROP) exploitation.

#### Q9: Explain Data Execution Prevention (DEP) / NX compatibility.
**Answer**: DEP is a security mitigation that marks memory pages (such as stack and heap) as non-executable, preventing code execution from write-only segments to block buffer overflow exploits.

#### Q10: What is a PE section?
**Answer**: A section is a named, contiguous block of virtual memory that houses specific types of data or code, such as '.text' for executable instructions or '.data' for initialized global variables.

#### Q11: What is the significance of the '.rsrc' section in a PE binary?
**Answer**: It holds resources used by the binary, including icons, dialog boxes, strings, and manifest files.

#### Q12: What does the '.reloc' section do?
**Answer**: It contains relocation tables that allow the loader to adjust absolute memory addresses if the binary cannot be loaded at its preferred Image Base address.

#### Q13: Explain the difference between virtual size and raw size of a PE section.
**Answer**: Virtual size is the size of the section when loaded into RAM, while raw size is the size of the section on disk. Virtual size can exceed raw size due to zero-initialized variables.

#### Q14: What is the Import Address Table (IAT)?
**Answer**: The IAT contains pointers to dynamic library functions imported by the binary. When loaded, the OS resolves these pointers to their actual addresses in memory.

#### Q15: What is the Export Directory in a PE binary?
**Answer**: A structure listing functions and symbols that the binary exports to be consumed by other modules (typically found in DLLs).

#### Q16: What is an API import ordinal?
**Answer**: An import ordinal is a numeric index used to import a function from a DLL instead of importing it by name, which is sometimes used to obscure the imported function's identity.

#### Q17: How does static malware analysis differ from dynamic analysis?
**Answer**: Static analysis inspects file structures, headers, and codes without execution, which is fast and safe. Dynamic analysis runs the binary in a sandbox, monitoring behaviors at the cost of execution hazard and VM latency.

#### Q18: What are the risks of dynamic sandboxing?
**Answer**: It runs the binary, presenting virtual memory execution risks, VM escape hazards, and vulnerability to malware that detects sandbox environments and remains dormant.

#### Q19: What is sandbox-aware malware?
**Answer**: Malware that checks for virtualized drivers, low CPU core counts, or lack of mouse movements to determine if it is running in a sandbox, delaying execution to evade dynamic detection.

#### Q20: What are cryptographic signatures (hashes) in antivirus tools?
**Answer**: Unique cryptographic hashes (MD5, SHA-256) of known malware samples compared against lookup tables, failing if a single byte in the malware changes.

#### Q21: Define zero-day attacks.
**Answer**: Exploits or malware stubs that target previously unknown vulnerabilities or have not yet been cataloged by signature databases.

#### Q22: Explain polymorphic malware.
**Answer**: Malware that alters its signature (e.g. encrypting its code with a different key on each infection) while keeping its core payload intact, easily bypassing static signature scanners.

#### Q23: What is a software packer?
**Answer**: A utility that compresses or encrypts an executable program on disk, wrapping it with an unpacking stub that decrypts it into memory at runtime to hide static code from scanners.

#### Q24: How does packing affect section entropy in a PE file?
**Answer**: Packed code represents high-randomness byte distributions, causing section entropy to spike (typically above 7.2 out of 8.0).

#### Q25: What is Shannon entropy?
**Answer**: A mathematical measure of randomness in a dataset, calculated as the negative sum of byte probabilities multiplied by their base-2 logarithms.

#### Q26: Why is a zero checksum in the PE Optional Header suspicious?
**Answer**: Many compilers calculate a checksum header. A checksum value of 0 suggests the binary has been modified post-compilation, a common indicator of signature tampering or patching.

#### Q27: What does the 'Subsystem' field in the PE Optional Header specify?
**Answer**: It defines the execution environment required by the binary, such as a command-line interface (Console Subsystem) or a graphical interface (Windows GUI Subsystem).

#### Q28: What are DLL Characteristics?
**Answer**: A bitmask in the optional header specifying security mitigations and execution properties, such as high entropy ASLR compatibility and DEP support.

#### Q29: Explain the role of the 'AddressOfEntryPoint' in PE files.
**Answer**: The relative virtual address (RVA) where execution begins when the loader transfers control to the loaded executable image.

#### Q30: What is static feature extraction?
**Answer**: The process of parsing file files (like PE structures) using library code to extract structural metrics without executing the binary.


---

### Category B: Basic to Intermediate Python & Streamlit (Q31–Q60)

#### Q31: What Python library is used for PE file parsing in this project?
**Answer**: The 'pefile' library, which parses Windows PE structures and maps COFF, optional, sections, imports, and resource directories.

#### Q32: What is Streamlit?
**Answer**: An open-source Python framework used to build and deploy interactive, data-driven web applications with minimal front-end coding.

#### Q33: How does Streamlit handle state between user interactions?
**Answer**: Streamlit reruns the script from top to bottom on each interaction, utilizing the `st.session_state` dictionary to persist variables across reruns.

#### Q34: Explain the purpose of `st.cache_resource` in Streamlit.
**Answer**: It caches global, non-serializable resources (such as database connections or machine learning models) so they are loaded once and shared across sessions.

#### Q35: How do you render a multi-page app in Streamlit?
**Answer**: By creating a `pages/` directory in the main folder. Streamlit automatically detects files inside it and renders them as side navigation routes.

#### Q36: What does `st.set_page_config` do?
**Answer**: Configures default page parameters such as the title page tab text, custom emojis, layout mode (wide vs centered), and sidebar states.

#### Q37: How does `st.dataframe` differ from `st.table`?
**Answer**: `st.dataframe` renders an interactive, sortable grid, whereas `st.table` renders a static HTML table.

#### Q38: What widget is used to accept files in Streamlit?
**Answer**: The `st.file_uploader` widget, which returns a file-like byte buffer object representing the uploaded file.

#### Q39: How do you read uploaded file bytes in Streamlit?
**Answer**: By calling the `.read()` method on the object returned by the `st.file_uploader` widget.

#### Q40: What is joblib and why is it used?
**Answer**: A serialization library optimized for large numpy-based objects, used to persist and load Scikit-Learn transformers and estimators.

#### Q41: How do you load a joblib file in Python?
**Answer**: Using `joblib.load('filename.joblib')`.

#### Q42: What is a pandas DataFrame?
**Answer**: A 2D, size-mutable, tabular data structure with labeled axes (rows and columns), used for data cleaning and transformations.

#### Q43: How do you convert a Python dictionary to a pandas DataFrame?
**Answer**: Using `pd.DataFrame([dictionary_name])`.

#### Q44: Explain the purpose of `os.path` / `pathlib` in this project.
**Answer**: Resolving absolute paths dynamically, ensuring project paths map correctly across Windows, macOS, and Linux nodes.

#### Q45: Why is logging important in a production model?
**Answer**: To audit operations, track performance metrics, trace execution errors, and record input telemetry for auditing.

#### Q46: What is YAML and where is it used in the project?
**Answer**: A human-readable data serialization standard, used to configure logging behaviors and default model settings (`config/logging.yaml`).

#### Q47: What does the Python built-in library `runpy` do?
**Answer**: It executes Python scripts in a separate context without importing them, used by the CLI runner interface.

#### Q48: How do you catch a PE format exception in Python?
**Answer**: By importing `pefile` and wrapping the parser inside a `try-except pefile.PEFormatError` block.

#### Q49: Explain the difference between packages and modules in Python.
**Answer**: A module is a single Python script (.py file), while a package is a directory containing modules and an `__init__.py` file.

#### Q50: What does `__init__.py` do?
**Answer**: It marks a directory as a Python package and runs initializations when the package is imported.

#### Q51: Explain relative imports in Python.
**Answer**: Imports that use leading dots to resolve modules relative to the current module's directory location (e.g. `from .utils import config`).

#### Q52: Why use `st.plotly_chart` instead of matplotlib in Streamlit?
**Answer**: Plotly charts are interactive (zoom, hover tooltips), whereas matplotlib generates static images.

#### Q53: What does the `st.columns` layout widget do?
**Answer**: Splits the app view into multiple side-by-side columns to render grids or gauges.

#### Q54: How do you implement a download button in Streamlit?
**Answer**: Using `st.download_button`, specifying data bytes, target filename, and the mime-type (e.g. `application/pdf`).

#### Q55: What is virtualenv in Python?
**Answer**: A tool to create isolated Python environments, ensuring project libraries do not clash with system packages.

#### Q56: How do you write a unit test in pytest?
**Answer**: By writing a test script prefixed with `test_` containing functions prefixed with `test_` that assert code outcomes.

#### Q57: Explain pytest fixtures.
**Answer**: Functions that run before test assertions to provide setup data, mock clients, or configuration configurations.

#### Q58: What is standard output (stdout) redirection?
**Answer**: Directing print streams to custom log files or memory buffers (such as capturing command outputs during tests).

#### Q59: How do you raise a custom exception in Python?
**Answer**: By defining a class that inherits from `Exception` and calling `raise CustomException('message')`.

#### Q60: What does `sys.path` represent?
**Answer**: A list of directory strings where Python searches for modules when resolving import directives.


---

### Category C: Intermediate Machine Learning & Preprocessing (Q61–Q90)

#### Q61: What is preprocessing in machine learning?
**Answer**: The process of cleaning raw data, resolving missing values, scaling values, and encoding categorical variables before training.

#### Q62: Explain numerical imputation.
**Answer**: The process of filling missing or null values in numerical columns with statistical substitutes (such as column means or medians).

#### Q63: Why prefer median imputation over mean imputation?
**Answer**: Medians are robust against outliers, preventing skewed distributions when features (like file size) have long tails.

#### Q64: Explain categorical imputation.
**Answer**: Filling missing values in categorical fields with placeholders or the most frequent category (mode).

#### Q65: What is One-Hot Encoding?
**Answer**: A technique to convert categorical strings into binary columns (1s and 0s), allowing models to process non-numerical labels.

#### Q66: Explain standard scaling (StandardScaler).
**Answer**: Standardization that shifts and scales columns to achieve zero mean and unit variance, preventing large values from dominating weights.

#### Q67: What is the difference between StandardScaler and MinMaxScaler?
**Answer**: StandardScaler scales data to zero mean and unit variance, while MinMaxScaler scales data strictly between 0 and 1.

#### Q68: What is a Scikit-Learn Pipeline?
**Answer**: A tool that chains data preprocessing steps and model estimators together, preventing data leakage during cross-validation.

#### Q69: What is ColumnTransformer?
**Answer**: A Scikit-Learn class that applies different transformations (imputations, scalers) to specific columns in a dataset.

#### Q70: What is data leakage?
**Answer**: When information from the test dataset is inadvertently used to train the model, resulting in overly optimistic validation scores.

#### Q71: How does ColumnTransformer prevent data leakage?
**Answer**: By fitting transformers on the training split only and applying those parameters to testing partitions without recalculating statistics.

#### Q72: Explain the concept of training and validation splits.
**Answer**: Dividing a dataset into a training subset to fit parameters and a validation subset to evaluate classification boundaries.

#### Q73: What is Stratified Splitting?
**Answer**: Splitting a dataset such that the proportion of classes (malicious vs legitimate) remains identical across training and testing partitions.

#### Q74: Why is stratified splitting critical for imbalanced data?
**Answer**: It ensures that small minority classes are adequately represented in both training and testing partitions, preventing training bias.

#### Q75: What is class imbalance?
**Answer**: When one class is significantly more numerous than another (e.g. 70% malware vs 30% benign files), biasing baseline predictions.

#### Q76: Explain cross-validation.
**Answer**: A validation technique where the dataset is split into K folds; the model is trained on K-1 folds and tested on the remaining fold, repeating K times.

#### Q77: What is Stratified K-Fold?
**Answer**: Cross-validation where each of the K folds maintains the same class distribution ratio as the original dataset.

#### Q78: Define hyperparameter tuning.
**Answer**: The process of searching for the optimal settings of a model (such as tree count or max depth) that are set before training.

#### Q79: How does RandomizedSearchCV differ from GridSearchCV?
**Answer**: GridSearchCV tests every combination of parameters, while RandomizedSearchCV samples a fixed number of combinations, saving computation time.

#### Q80: What is cross-validation scoring?
**Answer**: Evaluating validation metrics across K folds to obtain average scores, reducing variance in performance evaluations.

#### Q81: Define overfitting in machine learning.
**Answer**: When a model learns details and noise in the training set so well that it performs poorly on unseen validation data.

#### Q82: Define underfitting.
**Answer**: When a model is too simple to learn underlying patterns, yielding poor accuracy on both training and test subsets.

#### Q83: How does high model variance relate to overfitting?
**Answer**: High variance means predictions are highly sensitive to small changes in training data, indicating overfitting.

#### Q84: What is the bias-variance trade-off?
**Answer**: The tension between bias (error from simplistic assumptions) and variance (error from over-sensitivity to training data).

#### Q85: What is feature selection?
**Answer**: Selecting a subset of relevant features for model training, reducing dimensionality, training latency, and noise.

#### Q86: How do decision trees split features?
**Answer**: By choosing splits that maximize information gain or minimize impurity metrics like Gini or Entropy.

#### Q87: What is Gini impurity?
**Answer**: A metric measuring how often a randomly chosen element from the set would be incorrectly labeled if labeled randomly.

#### Q88: Explain ensemble learning.
**Answer**: Combining predictions from multiple base models (weak learners) to generate a robust ensemble prediction.

#### Q89: What is bagging?
**Answer**: Bootstrap Aggregating, fitting multiple independent estimators on bootstrap samples and voting on classifications (e.g. Random Forest).

#### Q90: What is boosting?
**Answer**: Fitting estimators sequentially, with each tree correcting errors made by preceding trees (e.g. AdaBoost, Gradient Boosting).


---

### Category D: Advanced Ensemble Algorithms & Optimization (Q91–Q120)

#### Q91: Explain how Random Forest operates.
**Answer**: An ensemble of decision trees trained on bootstrap samples. For each split, it selects a random subset of features, reducing tree correlation.

#### Q92: Why is Random Forest less prone to overfitting than a single Decision Tree?
**Answer**: By averaging predictions across many uncorrelated trees, it reduces overall variance without increasing bias.

#### Q93: Explain AdaBoost classification logic.
**Answer**: AdaBoost fits weak decision stumps sequentially. Misclassified samples receive higher weights, forcing the next tree to focus on them.

#### Q94: Explain Gradient Boosting classification logic.
**Answer**: Gradient Boosting trains decision trees sequentially. Each new tree is fit to the negative gradient of the loss function (residuals).

#### Q95: Compare Random Forest and Gradient Boosting.
**Answer**: Random Forest trains trees in parallel and averages results. Gradient Boosting trains sequentially, correcting errors step-by-step.

#### Q96: Why does AdaBoost fail on identical samples with contradictory labels?
**Answer**: If identical samples have alternating labels, no split can improve classification, making the weak learner no better than random guessing.

#### Q97: What metric does Scikit-Learn use to evaluate Random Forest splits by default?
**Answer**: The Gini Impurity metric.

#### Q98: What is tree pruning?
**Answer**: Removing nodes that provide little power to prevent overfitting and reduce model size.

#### Q99: What does the parameter 'n_estimators' control?
**Answer**: The number of trees in the forest or boosting ensemble.

#### Q100: What does 'max_depth' specify?
**Answer**: The maximum level of splits allowed for each tree in the forest.

#### Q101: What is 'min_samples_split'?
**Answer**: The minimum number of samples required to split an internal tree node.

#### Q102: What is 'min_samples_leaf'?
**Answer**: The minimum number of samples required to be at a leaf node, smoothing splits.

#### Q103: Explain out-of-bag (OOB) error.
**Answer**: An evaluation metric for bagging classifiers calculated using training samples that were not included in bootstrap samples.

#### Q104: How does class weighting address imbalanced datasets?
**Answer**: By assigning higher loss penalties to misclassifications of minority classes, forcing the classifier to balance its boundaries.

#### Q102: Define the Accuracy metric.
**Answer**: The ratio of correct predictions (TP + TN) to total samples, which can be misleading on imbalanced datasets.

#### Q106: Define Precision.
**Answer**: The ratio of correct positive predictions to total predicted positives (TP / (TP + FP)), measuring false alarm risk.

#### Q107: Define Recall (Sensitivity).
**Answer**: The ratio of correct positive predictions to total actual positives (TP / (TP + FN)), measuring slip risk.

#### Q108: What is the F1-Score?
**Answer**: The harmonic mean of Precision and Recall, providing a balanced metric for evaluating classifier performance.

#### Q109: Define True Positive Rate (TPR).
**Answer**: The ratio of actual legitimate files correctly allowed: TP / (TP + FN).

#### Q110: Define True Negative Rate (TNR / Specificity).
**Answer**: The ratio of actual malicious files correctly blocked: TN / (TN + FP).

#### Q111: Define False Positive Rate (FPR).
**Answer**: The ratio of malicious files misclassified as legitimate: FP / (TN + FP), representing security evasion risk.

#### Q112: Define False Negative Rate (FNR).
**Answer**: The ratio of legitimate files flagged as malicious: FN / (TP + FN), representing false alarm risk.

#### Q113: What is a Confusion Matrix?
**Answer**: A tabular grid layout comparing actual labels against model predictions across True Negatives, False Positives, False Negatives, and True Positives.

#### Q112: Why is FPR critical in static malware scanners?
**Answer**: Because a false positive means malware is classified as clean, allowing malicious code to run undetected on the host.

#### Q115: What is the ROC Curve?
**Answer**: A plot of the True Positive Rate against the False Positive Rate at various classification thresholds.

#### Q116: What is Area Under the Curve (AUC)?
**Answer**: A performance metric summarizing the ROC curve, measuring the model's ability to distinguish between classes.

#### Q117: Explain Precision-Recall Curves.
**Answer**: A plot of Precision against Recall at various thresholds, preferred for highly imbalanced datasets.

#### Q118: What is hyperparameter search space grid?
**Answer**: The defined dictionary range of parameters tested during RandomizedSearchCV tuning loops.

#### Q119: Explain the role of randomized seeds (`random_state`) in machine learning.
**Answer**: Ensuring splits, initializations, and tuning loops are reproducible across runs.

#### Q120: What is the impact of removing collinear features?
**Answer**: Reduces model size and training time while improving interpretability by removing redundant correlations.


---

### Category E: Explainable AI (XAI) & Tree Traversal Math (Q121–Q145)

#### Q121: What is Explainable AI (XAI)?
**Answer**: A suite of methods that make machine learning models transparent, explaining how inputs influence outputs.

#### Q122: Why is XAI critical in cybersecurity deployment?
**Answer**: Security teams must understand the reasons behind alerts to verify threats and prevent alert fatigue.

#### Q123: How does TrustLens AI calculate local feature contributions?
**Answer**: By tracing the decision paths of individual samples across the Random Forest trees to calculate probability changes at each split node.

#### Q124: Write the equation for local feature contribution calculation.
**Answer**: Contribution(f) = (1/T) * sum_{t=1}^T sum_{n in path_t} [ P_t(C_child | n_split=f) - P_t(C_parent) ]

#### Q125: What does the probability delta represent in tree splits?
**Answer**: The change in prediction probability for the target class when moving from a parent node to a child node based on a feature split.

#### Q126: How does local explanation differ from global feature importance?
**Answer**: Global importance shows overall feature utility across training, while local explanation shows feature contributions for an individual file scan.

#### Q127: Explain how SHAP (SHapley Additive exPlanations) values work.
**Answer**: An XAI method based on cooperative game theory that calculates additive feature contributions by testing all feature combinations.

#### Q128: Why use path-based traversals instead of SHAP in this project?
**Answer**: Path-based traversals run significantly faster (<10 ms), enabling real-time explanation on Streamlit pages.

#### Q129: What is LIME (Local Interpretable Model-agnostic Explanations)?
**Answer**: An XAI method that fits an interpretable local surrogate model around an individual sample's prediction to approximate feature importances.

#### Q130: Explain the difference between model-agnostic and model-specific XAI.
**Answer**: Model-agnostic methods work on any model (e.g. LIME, SHAP), while model-specific methods leverage internal structures (e.g. tree traversals).

#### Q131: How does section entropy influence local contributions?
**Answer**: If a file has section entropy >7.2, splits using this feature pull the score towards malware, yielding a negative contribution delta.

#### Q132: How does the presence of ASLR influence local contributions?
**Answer**: Its presence increases the probability of legitimacy, yielding a positive contribution delta that raises the trust score.

#### Q133: How does the absence of DEP affect the final classification?
**Answer**: It triggers rule-based warning alerts and maps selected static structural indicators to potential MITRE ATT&CK® associations using heuristic/contextual rules.

#### Q134: Explain how feature importances are calculated globally in Random Forest.
**Answer**: By calculating the mean decrease in impurity (Gini) caused by splits using that feature across all trees in the forest.

#### Q135: What is the sum of local feature contributions for a sample?
**Answer**: The sum of contributions plus the base value (mean prediction of the training set) equals the model's final prediction probability.

#### Q136: What is a base value in local explainability?
**Answer**: The baseline prediction probability of the model (typically the mean target distribution of the training dataset).

#### Q137: How does the XAI engine handle categorical feature contributions?
**Answer**: By tracking the encoded binary indicator column from the preprocessor and mapping contributions back to the original category label.

#### Q138: Explain what a positive local contribution means.
**Answer**: The feature value pushed the prediction probability towards the target class (benign/legitimate).

#### Q139: Explain a negative local contribution.
**Answer**: The feature value pulled the prediction probability away from the target class, indicating malware traits.

#### Q140: How do rule-based heuristics complement machine learning predictions?
**Answer**: They capture known safety compliance parameters (like ASLR/DEP flags) that statistical models might miss in complex feature interactions.

#### Q141: Why avoid fabricated explanations in security tools?
**Answer**: Fabricated explanations can mislead analysts, leading to false confidence and compromised systems.

#### Q142: What is local explanation transparency?
**Answer**: Providing reproducible, model-derived local feature contribution estimates based on the decision paths of the trained model.

#### Q143: How are warnings generated from contribution scores?
**Answer**: By checking if a feature's local contribution is negative and its value crosses a security threshold, triggering a natural language alert.

#### Q144: What does a high positive contribution for 'CheckSum' indicate?
**Answer**: That the binary contains a valid, non-zero checksum matching compilation standards, raising the trust score.

#### Q145: Why map local contributions to a horizontal bar chart?
**Answer**: To help security analysts quickly distinguish between features that support and features that decrease trust.


---

### Category F: MITRE ATT&CK & Cybersecurity Compliance (Q146–Q165)

#### Q146: What is the MITRE ATT&CK Framework?
**Answer**: A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations, used to map defenses.

#### Q147: What are ATT&CK Tactics?
**Answer**: The tactical objectives of an attacker, such as Defense Evasion, Privilege Escalation, or Initial Access.

#### Q148: What are ATT&CK Techniques?
**Answer**: The specific methods used by attackers to achieve a tactic (e.g. Software Packing under Defense Evasion).

#### Q149: How does TrustLens AI interwork with the MITRE ATT&CK framework?
**Answer**: It uses heuristic contextual rules to associate selected static structural indicators with potential MITRE ATT&CK® techniques; these associations do not establish that a technique was actually executed.

#### Q150: What tactic does 'High Section Entropy' map to?
**Answer**: Defense Evasion, specifically technique T1027.002 (Software Packing).

#### Q151: What tactic does 'Missing ASLR/DEP' map to?
**Answer**: Potential Privilege Escalation, heuristically mapped to technique potential association (heuristic/contextual) (Exploitation for Privilege Escalation).

#### Q152: What tactic does 'Zero Checksum' map to?
**Answer**: Defense Evasion, specifically technique potential association (heuristic/contextual) (Subvert Trust Controls).

#### Q153: What tactic does 'Low Import Count' map to?
**Answer**: Defense Evasion, specifically technique T1027 (Obfuscated Files or Information).

#### Q154: What tactic does 'Image Size Mismatch' map to?
**Answer**: Defense Evasion, specifically technique potential association (heuristic/contextual) (Process Injection).

#### Q155: What tactic does 'Extension Spoofing' map to?
**Answer**: Defense Evasion, specifically technique potential association (heuristic/contextual) (Masquerading: Rename System Utilities).

#### Q156: Why map header anomalies to MITRE ATT&CK?
**Answer**: To provide compliance telemetry and help security teams coordinate threat mitigations.

#### Q157: Explain the significance of the MITRE mapping matrix page in the UI.
**Answer**: It acts as an interactive reference showing how structural file checks correspond to real-world adversary tactics.

#### Q158: What is compile-time security compliance?
**Answer**: Verifying that binaries are compiled with modern defense flags (like ASLR and DEP) to prevent exploits.

#### Q159: How does static compliance monitoring reduce security risks?
**Answer**: It identifies vulnerable binaries before execution, allowing administrators to block or isolate them.

#### Q160: What is a ROP chain exploit?
**Answer**: Return-Oriented Programming, an exploit technique where attackers hijack control flow using existing code snippets in memory, bypassed by ASLR.

#### Q161: How does DEP prevent stack buffer execution?
**Answer**: By marking the stack region as non-executable, causing the CPU to block attempts to run shellcode from the stack.

#### Q162: What is dynamic base flag in optional header?
**Answer**: A flag that indicates the binary is compatible with ASLR, allowing the OS to randomize its load address.

#### Q163: What is NX compat flag in optional header?
**Answer**: A flag indicating the binary is compatible with DEP/NX memory protections.

#### Q164: Define threat intelligence.
**Answer**: Organized, analyzed information about cyber threats and actor behaviors, used to protect assets.

#### Q165: How does mapping static telemetry to MITRE ATT&CK support security analysts?
**Answer**: It translates low-level binary properties into tactical intelligence, enabling rapid triage and investigation.


---

### Category G: Project Design, Testing & QA (Q166–Q180)

#### Q166: What software testing techniques did you apply to this project?
**Answer**: White Box testing for internal helper logic (such as entropy math) and Black Box testing for integration pipelines and CLI interfaces.

#### Q167: What tool executes your automated test cases?
**Answer**: The `pytest` testing framework.

#### Q168: Explain how you mock model loading in test suites.
**Answer**: By using `unittest.mock.patch` to bypass joblib file lookups and return mock classifier models, isolation testing code logic.

#### Q169: What is the size of the test suite implemented for TrustLens AI?
**Answer**: 32 automated unit, integration, and functional test cases covering all modules.

#### Q170: What does `test_preprocess.py` verify?
**Answer**: It validates entropy calculations, PE attribute extractions, and ColumnTransformer pipeline fits.

#### Q171: What does `test_predict.py` verify?
**Answer**: It validates local rule mitigation warnings, prediction schemas, and model-loading error handling.

#### Q172: What does `test_explanation.py` verify?
**Answer**: It validates path-based feature contribution traversals on Random Forest models.

#### Q173: What does `test_report.py` verify?
**Answer**: It asserts that PDF generation compiles a valid PDF byte stream starting with standard `%PDF` magic bytes.

#### Q174: What does `test_main.py` verify?
**Answer**: It verifies CLI scan execution pathways and JSON output formatting.

#### Q175: What happens if the required ML model artifacts are missing?
**Answer**: The application loads the trained model artifacts from the Models directory. If the required model artifacts cannot be loaded, the application reports a model-loading/inference error rather than fabricating a prediction.

#### Q176: How do you test security boundaries in your upload page?
**Answer**: By uploading malformed or non-PE files to verify that the uploader catches exceptions and does not crash.

#### Q177: What is performance latency testing?
**Answer**: Measuring the execution duration of code segments to verify they meet performance requirements.

#### Q178: How do you capture stdout in pytest?
**Answer**: Using the `capsys` fixture to read printed streams and assert CLI console output formats.

#### Q179: What is a bug log?
**Answer**: A record of discovered issues, their root causes, and resolutions maintained during development.

#### Q180: Name one critical bug you resolved during refactoring.
**Answer**: A KeyError on explanation printouts in `main.py` caused by a mismatch in refactored prediction keys, resolved by mapping outputs correctly.


---

### Category H: Guide & External Examiner Defense (Q181–Q200)

#### Q181: Explain the academic contribution of your B.Tech project.
**Answer**: TrustLens AI integrates static PE parsing with explainable AI tree traversals, delivering transparent pre-execution trust scoring and compliance mapping.

#### Q182: Why is your system designed as a support tool rather than an antivirus replacement?
**Answer**: Because static analysis evaluates structural properties. It does not monitor runtime actions or memory signatures, which are critical tasks handled by AV suites.

#### Q183: How does the system handle a non-Windows file format?
**Answer**: It validates headers for the DOS `MZ` magic bytes, raising a format exception and blocking processing if missing.

#### Q184: How would you adapt the system to handle Linux ELF binaries?
**Answer**: By importing an ELF parsing library (e.g. `pyelftools`), defining an ELF feature schema, and retraining classifiers on ELF datasets.

#### Q185: What is the computational latency of a standard file scan?
**Answer**: Inference, scaling, and explanations complete in approximately 42 milliseconds per scan.

#### Q186: How does your project demonstrate software engineering best practices?
**Answer**: Through modular package structures, absolute path resolvers, environment configuration overrides, and automated testing coverage.

#### Q187: How do you justify your choice of dataset?
**Answer**: The dataset contains 138,047 samples (including packed and benign files), providing a diverse training set for binary headers classification.

#### Q188: What would happen if an attacker forged PE headers to mimic a benign file?
**Answer**: Modifying header parameters (like alignments or sections) is constrained by OS execution rules. Forging them incorrectly will corrupt the file and prevent execution.

#### Q189: What are the security implications of utilizing python joblib serialized files?
**Answer**: Joblib files can execute arbitrary code during deserialization. TrustLens AI mitigates this by restricting loading to verified local assets.

#### Q190: How does the PDF generation service work?
**Answer**: It uses ReportLab to compile tables, banners, and matplotlib charts into a printable PDF report byte stream.

#### Q191: Why did you avoid using deep learning as the primary model?
**Answer**: Deep learning models require significant compute resources, while ensemble tree models achieve high accuracy on tabular data with low latency.

#### Q192: What is the memory footprint of your model assets?
**Answer**: The serialized Random Forest model is approximately 42 MB, making it lightweight enough to run on standard computers.

#### Q193: How does the system resolve missing values in incoming scans?
**Answer**: It applies the pre-fitted preprocessing pipeline, imputing missing numerical values with training column medians.

#### Q194: What is the role of the StandardScaler in feature parsing?
**Answer**: It standardizes feature scales, preventing larger columns (like file size) from dominating model weights.

#### Q195: How does the system handle missing model artifacts in production?
**Answer**: The application loads the trained model artifacts from the Models directory. If the required model artifacts cannot be loaded, the application reports a model-loading/inference error rather than fabricating a prediction.

#### Q196: How do you test for directory traversal in the uploader?
**Answer**: The uploader parses files in memory as bytes and does not write them to disk, preventing directory traversal vulnerabilities.

#### Q197: What MITRE tactic is associated with low import counts?
**Answer**: Defense Evasion (technique T1027, Obfuscated Files).

#### Q198: What is the contribution of the project guide in your research?
**Answer**: They provided guidance on structuring B.Tech reports, selecting datasets, and mapping anomalies to cybersecurity compliance standards.

#### Q199: How does the system handle encrypted sections?
**Answer**: It calculates section entropy; values above 7.2 suggest encryption, which triggers packing alerts.

#### Q200: What is the primary conclusion of your project?
**Answer**: Static multi-format analysis combined with ensemble classifiers provides a secure, efficient pre-execution threat scanner, with the PE model achieving 99.48% accuracy and explainable predictions.

#### Q201: How could you increase the model's accuracy and precision in the future without facing dataset copyright or redistribution issues?
**Answer**: By migrating to exclusively open-source, permissive datasets (like the EMBER dataset) or utilizing synthetic data generation (such as Generative Adversarial Networks or SMOTE). This allows us to expand our training corpus and improve model metrics legally without relying on proprietary third-party datasets.

