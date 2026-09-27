"""External real-world PDF benchmark evaluation for TrustLens AI.

This module evaluates a PDF-specific benchmark from labelled extracted features.
It intentionally does NOT claim to be the existing 10-feature multi-format model: the
CIC-Evasive-PDFMal2022 corpus exposes PDF-specific features rather than raw files.

The dataset CSV is not bundled with the project. Supply a legitimately obtained copy.
"""
from __future__ import annotations
import json
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

LABEL_MAP = {"Malicious": 0, "Benign": 1}
DROP_COLUMNS = ["Fine name", "header"]

def evaluate_csv(csv_path, test_size=0.30, random_state=42):
    df = pd.read_csv(csv_path)
    df = df[df["Class"].isin(LABEL_MAP)].copy()
    if df.empty:
        raise ValueError("No valid Malicious/Benign rows found.")
    y = df.pop("Class").map(LABEL_MAP).astype(int)
    X = df.drop(columns=[c for c in DROP_COLUMNS if c in df.columns])
    for c in X.columns:
        X[c] = pd.to_numeric(X[c], errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=random_state, stratify=y)
    pipe = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=random_state, n_jobs=-1)),
    ])
    pipe.fit(X_train, y_train)
    pred = pipe.predict(X_test)
    prob_malicious = pipe.predict_proba(X_test)[:, list(pipe.classes_).index(0)]
    cm = confusion_matrix(y_test, pred, labels=[0, 1])
    tp, fn, fp, tn = map(int, cm.ravel())
    return {
        "evaluation_type": "external_real_world_pdf_benchmark",
        "dataset": "CIC-Evasive-PDFMal2022",
        "total_samples": int(len(df)),
        "train_samples": int(len(y_train)),
        "test_samples": int(len(y_test)),
        "class_counts": {"malicious": int((y == 0).sum()), "benign": int((y == 1).sum())},
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision_malicious": float(precision_score(y_test, pred, pos_label=0, zero_division=0)),
        "recall_malicious": float(recall_score(y_test, pred, pos_label=0, zero_division=0)),
        "f1_malicious": float(f1_score(y_test, pred, pos_label=0, zero_division=0)),
        "roc_auc_malicious": float(roc_auc_score((y_test == 0).astype(int), prob_malicious)),
        "confusion_matrix": {"tp_malicious": tp, "fn_malicious": fn, "fp_malicious": fp, "tn_malicious": tn},
        "features_used": X.columns.tolist(),
        "note": "Independent PDF benchmark classifier using the corpus feature representation; not the existing TrustLens 10-feature synthetic model or raw-file prediction pipeline.",
    }, pipe

def save_evaluation(csv_path, output_dir):
    metrics, model = evaluate_csv(csv_path)
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    (out / "external_pdf_benchmark_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics, model
