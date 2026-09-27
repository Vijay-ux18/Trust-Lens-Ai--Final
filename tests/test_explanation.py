"""
Unit tests for Module 3a: Explainable AI (XAI) Engine.
"""

from unittest.mock import MagicMock

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from btech.explanation import explain_prediction


def test_explain_prediction_fallback() -> None:
    """Verify that fallback feature importance explanations compile correctly."""
    # Create simple preprocessor and mock model
    X_train = pd.DataFrame({"Machine": [332.0] * 5, "Characteristics": [258.0] * 5})

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "num",
                Pipeline([("imputer", SimpleImputer()), ("scaler", StandardScaler())]),
                ["Machine", "Characteristics"],
            )
        ]
    )
    preprocessor.fit(X_train)
    preprocessor.set_output(transform="pandas")

    # Mock model
    model = MagicMock()
    model.feature_importances_ = np.array([0.6, 0.4])

    raw_features = {"Machine": 332.0, "Characteristics": 258.0}

    result = explain_prediction(model, preprocessor, raw_features, target_class=1)

    assert "explanations" in result
    assert len(result["explanations"]) == 2
    assert result["explanations"][0]["feature_name"] in ["Machine", "Characteristics"]
    assert "transformed_value" in result["explanations"][0]


def test_explain_prediction_rf() -> None:
    """Verify explain_prediction path contribution logic for Random Forest."""
    X_train = pd.DataFrame(
        {"Machine": [332, 100, 332, 100, 332], "Characteristics": [258, 12, 258, 12, 258]}
    )
    y_train = pd.Series([1, 0, 1, 0, 1])

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "num",
                Pipeline([("imputer", SimpleImputer()), ("scaler", StandardScaler())]),
                ["Machine", "Characteristics"],
            )
        ]
    )
    X_proc = preprocessor.fit_transform(X_train)
    preprocessor.set_output(transform="pandas")

    # Fit real Random Forest model
    rf = RandomForestClassifier(n_estimators=3, random_state=42)
    rf.fit(X_proc, y_train)

    raw_features = {"Machine": 332, "Characteristics": 258}
    result = explain_prediction(rf, preprocessor, raw_features, target_class=1)

    assert "explanations" in result
    assert len(result["explanations"]) > 0
    assert "feature_name" in result["explanations"][0]
    assert "contribution_score" in result["explanations"][0]
    assert "influence_direction" in result["explanations"][0]


def test_explain_prediction_rf_with_standard_scaler() -> None:
    """Verify live-style XAI works with the multi-format StandardScaler pipeline."""
    from sklearn.preprocessing import StandardScaler

    X_train = pd.DataFrame(
        {
            "file_size_kb": [10.0, 20.0, 30.0, 40.0],
            "entropy": [2.0, 3.0, 7.5, 7.8],
            "has_executable_code": [0.0, 0.0, 1.0, 1.0],
            "has_obfuscation": [0.0, 0.0, 1.0, 1.0],
            "has_network_indicators": [0.0, 0.0, 1.0, 1.0],
            "has_macros_or_scripts": [0.0, 0.0, 1.0, 1.0],
            "is_encrypted_or_packed": [0.0, 0.0, 1.0, 1.0],
            "has_masquerading": [0.0, 0.0, 1.0, 1.0],
            "metadata_density": [0.5, 0.6, 0.1, 0.2],
            "suspicious_indicators_count": [0.0, 0.0, 6.0, 7.0],
        }
    )
    y_train = pd.Series([1, 1, 0, 0])
    scaler = StandardScaler().fit(X_train)
    rf = RandomForestClassifier(n_estimators=5, random_state=42)
    rf.fit(scaler.transform(X_train), y_train)

    raw_features = X_train.iloc[[0]].to_dict(orient="records")[0]
    target_class = int(rf.predict(scaler.transform(X_train.iloc[[0]]))[0])
    result = explain_prediction(rf, scaler, raw_features, target_class=target_class)

    assert len(result["raw_contributions"]) == 10
    assert len(result["explanations"]) == 3
    assert all("contribution_score" in item for item in result["explanations"])
