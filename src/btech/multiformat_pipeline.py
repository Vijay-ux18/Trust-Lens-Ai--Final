"""
Module 4b: Multi-Format Machine Learning Pipeline.
Synthesizes a multi-format feature dataset, trains a Random Forest classifier,
standardizes features, and serializes the assets.
"""

import json
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from btech.analyzers.normalization import FeatureNormalizer

MODEL_PATH = "models/multiformat_model.joblib"
PREPROCESSOR_PATH = "models/multiformat_preprocessor.joblib"
METRICS_PATH = "files/multiformat_metrics.json"


def generate_synthetic_data(num_samples: int = 5000) -> tuple[pd.DataFrame, pd.Series]:
    """
    Generate a balanced synthetic dataset representing common feature distributions
    across Safe, Low, Medium, High, and Critical files.
    """
    np.random.seed(42)
    records = []
    labels = []

    for _ in range(num_samples):
        # Choose if the file is legitimate (1) or malicious (0)
        label = np.random.choice([1, 0], p=[0.5, 0.5])

        # Format type distribution: document vs binary vs script
        fmt_type = np.random.choice(["document", "binary", "script"])

        file_size = np.random.exponential(scale=500.0) + 1.0

        # Initialize default benign feature values
        if fmt_type == "document":
            # Legitimate compressed documents (PDF/DOCX) naturally have high entropy
            entropy = np.random.uniform(7.0, 7.99)
        else:
            entropy = np.random.uniform(2.0, 5.5)

        has_executable = 0.0
        has_obfuscation = 0.0
        has_network = 0.0
        has_macros = 0.0
        is_encrypted = 0.0
        has_masquerading = 0.0
        meta_density = np.random.uniform(0.3, 0.9)

        if label == 1:
            # --- Legitimate / Benign ---
            if fmt_type == "document":
                # Benign documents often contain hyperlinks
                has_network = np.random.choice([0.0, 1.0], p=[0.4, 0.6])
                # Small percentage of documents can contain benign macros/scripts
                if np.random.rand() < 0.05:
                    has_macros = 1.0
                    has_executable = 1.0
            elif fmt_type == "script":
                has_macros = 1.0  # Script files naturally run code
                has_executable = 1.0
                has_network = np.random.choice([0.0, 1.0], p=[0.8, 0.2])
            elif fmt_type == "binary":
                # Unpacked benign binaries can have network checks
                has_network = np.random.choice([0.0, 1.0], p=[0.9, 0.1])
        else:
            # --- Malicious ---
            # Malicious files usually have stripped or suspicious metadata
            meta_density = np.random.uniform(0.0, 0.4)

            # Select a random malicious profile to simulate different types of malware
            mal_profile = np.random.choice(
                [
                    "macro_malware",
                    "obfuscated_script",
                    "masquerading_binary",
                    "packed_trojan",
                    "exploit_pdf",
                ]
            )

            if mal_profile == "macro_malware":
                # Office document with malicious macros
                fmt_type = "document"
                entropy = np.random.uniform(7.0, 7.99)
                has_macros = 1.0
                has_executable = 1.0
                has_network = np.random.choice([0.0, 1.0], p=[0.2, 0.8])
                has_obfuscation = np.random.choice([0.0, 1.0], p=[0.5, 0.5])

            elif mal_profile == "obfuscated_script":
                # Malicious obfuscated PowerShell/JS dropper
                fmt_type = "script"
                entropy = np.random.uniform(3.5, 6.5)
                has_macros = 1.0
                has_executable = 1.0
                has_obfuscation = 1.0
                has_network = np.random.choice([0.0, 1.0], p=[0.1, 0.9])

            elif mal_profile == "masquerading_binary":
                # Binary spoofing extensions (e.g., .exe masquerading as .pdf or .txt)
                fmt_type = "document"
                entropy = np.random.uniform(7.0, 7.99)
                has_masquerading = 1.0
                has_executable = 1.0
                has_network = np.random.choice([0.0, 1.0])
                has_obfuscation = np.random.choice([0.0, 1.0], p=[0.4, 0.6])

            elif mal_profile == "packed_trojan":
                # Packed malicious PE binary
                fmt_type = "binary"
                entropy = np.random.uniform(7.2, 8.0)  # High entropy binary (packed)
                has_executable = 1.0
                is_encrypted = 1.0
                has_obfuscation = 1.0
                has_network = np.random.choice([0.0, 1.0])

            elif mal_profile == "exploit_pdf":
                # PDF containing malicious JS exploit stream
                fmt_type = "document"
                entropy = np.random.uniform(7.0, 7.99)
                has_macros = 1.0  # PDF JS is mapped as macros/script execution flag
                has_executable = 1.0
                has_network = 1.0
                has_obfuscation = np.random.choice([0.0, 1.0], p=[0.6, 0.4])

        # Calculate combined suspicious count
        susp_count = 0.0
        if has_executable == 1.0:
            susp_count += 1.0
        if has_obfuscation == 1.0:
            susp_count += 1.0
        if has_network == 1.0:
            susp_count += 1.0
        if has_macros == 1.0:
            susp_count += 1.0
        if is_encrypted == 1.0:
            susp_count += 1.0
        if has_masquerading == 1.0:
            susp_count += 2.0

        record = {
            "file_size_kb": file_size,
            "entropy": entropy,
            "has_executable_code": has_executable,
            "has_obfuscation": has_obfuscation,
            "has_network_indicators": has_network,
            "has_macros_or_scripts": has_macros,
            "is_encrypted_or_packed": is_encrypted,
            "has_masquerading": has_masquerading,
            "metadata_density": meta_density,
            "suspicious_indicators_count": susp_count,
        }
        records.append(record)
        labels.append(label)

    df_X = pd.DataFrame(records)
    ser_y = pd.Series(labels)
    return df_X, ser_y


def train_multiformat_pipeline() -> None:
    """
    Train and save the multi-format pipeline and Random Forest model assets,
    using Stratified 5-Fold Cross-Validation as requested in the IEEE paper.
    """
    print("Generating training dataset for multi-format pipeline...")
    X, y = generate_synthetic_data(10000)

    # Split train-test (70:30)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    # Fit StandardScaler preprocessor on training data
    print("Fitting features scaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    model = RandomForestClassifier(
        n_estimators=100, max_depth=6, min_samples_leaf=5, class_weight="balanced", random_state=42
    )

    # 5-Fold Stratified Cross Validation
    print("Evaluating Random Forest Classifier via Stratified 5-Fold CV...")
    from sklearn.model_selection import StratifiedKFold, cross_validate
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_validate(
        model, X_train_scaled, y_train, cv=cv, scoring=["accuracy", "precision", "recall", "f1"]
    )

    print(f"CV Mean Accuracy:  {cv_scores['test_accuracy'].mean() * 100:.2f}%")
    print(f"CV Mean Precision: {cv_scores['test_precision'].mean() * 100:.2f}%")
    print(f"CV Mean Recall:    {cv_scores['test_recall'].mean() * 100:.2f}%")
    print(f"CV Mean F1-Score:  {cv_scores['test_f1'].mean() * 100:.2f}%")

    # Fit the model on the full training set
    model.fit(X_train_scaled, y_train)

    # Evaluate on the holdout test set (30%)
    from sklearn.metrics import confusion_matrix
    y_pred = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    
    tpr = tp / (tp + fn)
    tnr = tn / (tn + fp)
    fpr = fp / (fp + tn)
    fnr = fn / (fn + tp)
    
    print("\n--- Final Model Holdout Evaluation ---")
    print(f"Test Accuracy: {acc * 100:.2f}%")
    print(f"True Positive Rate (TPR): {tpr * 100:.2f}%")
    print(f"True Negative Rate (TNR): {tnr * 100:.2f}%")
    print(f"False Positive Rate (FPR): {fpr * 100:.2f}%")
    print(f"False Negative Rate (FNR): {fnr * 100:.2f}%")

    # Save assets to files
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, PREPROCESSOR_PATH)
    print(f"\nModel assets saved to {MODEL_PATH} and {PREPROCESSOR_PATH}")

    # Save performance metrics JSON
    os.makedirs(os.path.dirname(METRICS_PATH), exist_ok=True)
    report = classification_report(y_test, y_pred, output_dict=True)

    metrics = {
        "accuracy": acc,
        "cv_accuracy_mean": cv_scores['test_accuracy'].mean(),
        "cv_precision_mean": cv_scores['test_precision'].mean(),
        "cv_recall_mean": cv_scores['test_recall'].mean(),
        "cv_f1_mean": cv_scores['test_f1'].mean(),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "tpr": tpr,
        "tnr": tnr,
        "fpr": fpr,
        "fnr": fnr,
        "classification_report": report,
        "feature_importances": dict(zip(X.columns, model.feature_importances_.tolist())),
    }

    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=4)
    print(f"Metrics saved to {METRICS_PATH}")


if __name__ == "__main__":
    train_multiformat_pipeline()
