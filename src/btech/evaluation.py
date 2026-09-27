"""
Module 2b: ML Model Evaluation.
Handles stratified cross-validation evaluation and final holdout metric calculations.
"""

from typing import Any, Dict

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import cross_val_score


def evaluate_with_cv(
    models: Dict[str, Any], X: Any, y: Any, cv: Any
) -> Dict[str, Dict[str, float]]:
    """
    Evaluate candidate models using Stratified K-Fold cross-validation.
    Returns calculated mean accuracy, precision, recall, and f1 scores.
    """
    cv_results = {}

    for name, model in models.items():
        # Stratified K-fold metrics calculation
        accs = cross_val_score(model, X, y, cv=cv, scoring="accuracy", n_jobs=-1)
        precs = cross_val_score(model, X, y, cv=cv, scoring="precision", n_jobs=-1)
        recs = cross_val_score(model, X, y, cv=cv, scoring="recall", n_jobs=-1)
        f1s = cross_val_score(model, X, y, cv=cv, scoring="f1", n_jobs=-1)

        cv_results[name] = {
            "Accuracy": float(np.mean(accs)),
            "Precision": float(np.mean(precs)),
            "Recall": float(np.mean(recs)),
            "F1-Score": float(np.mean(f1s)),
        }

    return cv_results


def compute_evaluation_metrics(y_true: Any, y_pred: Any) -> Dict[str, Any]:
    """
    Compute classification metrics: Accuracy, TPR, TNR, FPR, FNR, and Confusion Matrix.
    """
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred)

    tn, fp, fn, tp = cm.ravel()

    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "confusion_matrix": cm.tolist(),
        "tpr": tpr,
        "tnr": tnr,
        "fpr": fpr,
        "fnr": fnr,
    }
