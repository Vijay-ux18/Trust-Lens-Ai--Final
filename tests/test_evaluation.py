"""
Unit tests for Module 2b: ML Model Evaluation.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold

from btech.evaluation import compute_evaluation_metrics, evaluate_with_cv


def test_evaluate_with_cv() -> None:
    """Verify cross-validation returns validation scores for candidate models."""
    X_train = pd.DataFrame({"num__Machine": [332] * 20, "num__SizeOfOptionalHeader": [224] * 20})
    y_train = pd.Series([1, 0] * 10)

    models = {"Random Forest": RandomForestClassifier(n_estimators=10, random_state=42)}

    cv = StratifiedKFold(n_splits=2, shuffle=True, random_state=42)
    results = evaluate_with_cv(models, X_train, y_train, cv)

    assert "Random Forest" in results
    assert "Accuracy" in results["Random Forest"]
    assert "Precision" in results["Random Forest"]
    assert "Recall" in results["Random Forest"]
    assert "F1-Score" in results["Random Forest"]

    # Assert values are ratios (between 0.0 and 1.0)
    assert 0.0 <= results["Random Forest"]["Accuracy"] <= 1.0


def test_compute_evaluation_metrics() -> None:
    """Verify calculation of accuracy, confusion matrix, and rate metrics."""
    y_true = [1, 0, 1, 0, 1]
    y_pred = [1, 1, 1, 0, 0]

    # TP = 2 (indices 0, 2 predicted 1, true 1)
    # TN = 1 (index 3 predicted 0, true 0)
    # FP = 1 (index 1 predicted 1, true 0)
    # FN = 1 (index 4 predicted 0, true 1)
    # Accuracy = 3/5 = 0.6
    # TPR = 2/(2+1) = 2/3 = 0.66667
    # TNR = 1/(1+1) = 0.5
    # FPR = 1/(1+1) = 0.5
    # FNR = 1/(2+1) = 0.33333

    metrics = compute_evaluation_metrics(y_true, y_pred)

    assert metrics["accuracy"] == 0.6
    assert abs(metrics["tpr"] - 0.66667) < 1e-4
    assert metrics["tnr"] == 0.5
    assert metrics["fpr"] == 0.5
    assert abs(metrics["fnr"] - 0.33333) < 1e-4
    assert metrics["confusion_matrix"] == [[1, 1], [1, 2]]
