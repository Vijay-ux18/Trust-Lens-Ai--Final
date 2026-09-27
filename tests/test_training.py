"""
Unit tests for Module 2a: ML Model Training.
"""

from unittest.mock import MagicMock, patch

import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from btech.training import train_candidate_models, tune_best_model


def test_train_candidate_models() -> None:
    """Verify candidate classifiers are trained successfully with distinguishable features."""
    # Create simple distinguishable mock training data
    # (AdaBoost requires features better than random guessing)
    X_train = pd.DataFrame(
        {
            "num__Machine": [332, 100, 332, 100, 332, 100],
            "num__SizeOfOptionalHeader": [224, 12, 224, 12, 224, 12],
        }
    )
    y_train = pd.Series([1, 0, 1, 0, 1, 0])

    models = train_candidate_models(X_train, y_train)

    assert "Random Forest" in models
    assert "AdaBoost" in models
    assert "Gradient Boosting" in models

    # Assert they are fitted models
    assert hasattr(models["Random Forest"], "classes_")
    assert hasattr(models["AdaBoost"], "classes_")


@patch("btech.training.RandomizedSearchCV")
def test_tune_best_model(mock_search_class: MagicMock) -> None:
    """Verify hyperparameter search is set up and fits correctly using simple mock."""
    X_train = pd.DataFrame({"num__Machine": [332] * 10, "num__SizeOfOptionalHeader": [224] * 10})
    y_train = pd.Series([1, 0] * 5)

    # Mock search instance return values
    mock_search_instance = MagicMock()
    mock_best_estimator = RandomForestClassifier()
    mock_best_params = {"n_estimators": 50}
    mock_search_instance.best_estimator_ = mock_best_estimator
    mock_search_instance.best_params_ = mock_best_params
    mock_search_class.return_value = mock_search_instance

    tuned, params = tune_best_model(X_train, y_train, "Random Forest", cv=2)

    assert tuned == mock_best_estimator
    assert params == mock_best_params
    mock_search_class.assert_called_once()
