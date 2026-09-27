"""
Unit tests for Module 2: ML Pipeline & Training Orchestrator.
"""

import os
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from btech.pipeline import load_and_preprocess, run_pipeline


@patch("btech.pipeline.download_dataset")
@patch("pandas.read_csv")
@patch("btech.pipeline.preprocess_dataset")
def test_load_and_preprocess(
    mock_preprocess: MagicMock, mock_read_csv: MagicMock, mock_download: MagicMock
) -> None:
    """Verify loading and initial clean splits."""
    mock_df = pd.DataFrame({"Name": ["test.exe"], "md5": ["hash"], "legitimate": [1]})
    mock_read_csv.return_value = mock_df

    X_mock = pd.DataFrame({"Machine": [332]})
    y_mock = pd.Series([1])
    mock_preprocess.return_value = (X_mock, y_mock)

    X, y = load_and_preprocess()

    mock_download.assert_called_once()
    mock_read_csv.assert_called_once()
    mock_preprocess.assert_called_once_with(mock_df)

    assert X.equals(X_mock)
    assert y.equals(y_mock)


@patch("btech.pipeline.load_and_preprocess")
@patch("btech.pipeline.train_candidate_models")
@patch("btech.pipeline.evaluate_with_cv")
@patch("btech.pipeline.tune_best_model")
@patch("btech.pipeline.compute_evaluation_metrics")
@patch("btech.pipeline.save_assets")
@patch("builtins.open")
def test_run_pipeline_orchestrator(
    mock_open: MagicMock,
    mock_save: MagicMock,
    mock_compute: MagicMock,
    mock_tune: MagicMock,
    mock_eval: MagicMock,
    mock_train: MagicMock,
    mock_load: MagicMock,
) -> None:
    """Verify that run_pipeline correctly coordinates all modular operations."""
    # Mock data splits
    X_mock = pd.DataFrame({"Machine": [332] * 10, "Characteristics": [258] * 10})
    y_mock = pd.Series([1, 0] * 5)
    mock_load.return_value = (X_mock, y_mock)

    # Mock models and outputs
    mock_models = {"Random Forest": MagicMock()}
    mock_train.return_value = mock_models

    mock_eval.return_value = {
        "Random Forest": {"Accuracy": 0.99, "Precision": 0.99, "Recall": 0.99, "F1-Score": 0.99}
    }

    mock_best_model = MagicMock()
    mock_tune.return_value = (mock_best_model, {"n_estimators": 50})

    mock_compute.return_value = {
        "accuracy": 0.99,
        "tpr": 0.99,
        "tnr": 0.99,
        "fpr": 0.01,
        "fnr": 0.01,
        "confusion_matrix": [[5, 0], [0, 5]],
    }

    # Run orchestrator
    run_pipeline()

    mock_load.assert_called_once()
    mock_train.assert_called_once()
    mock_eval.assert_called_once()
    mock_tune.assert_called_once()
    mock_compute.assert_called_once()
    mock_save.assert_called_once()
    mock_open.assert_called_once()
