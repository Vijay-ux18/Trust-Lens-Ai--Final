import os
import sys
import pytest
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier

# Ensure src is in the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from btech.ml_experiment import DATASET_PATH, OUTPUT_DIR, run_experiment

@pytest.mark.skipif(not os.path.exists(DATASET_PATH), reason="Dataset not present")
def test_dataset_exists():
    assert os.path.exists(DATASET_PATH), f"Dataset missing: {DATASET_PATH}"

@pytest.mark.skipif(not os.path.exists(DATASET_PATH), reason="Dataset not present")
def test_dataset_loadable():
    df = pd.read_csv(DATASET_PATH, sep='|')
    assert not df.empty, "Dataset is empty"
    assert 'legitimate' in df.columns, "Target column 'legitimate' not found"

@pytest.mark.skipif(not os.path.exists(DATASET_PATH), reason="Dataset not present")
def test_run_experiment_creates_outputs():
    # Run the experiment
    # This might take a few seconds due to GridSearchCV
    run_experiment()
    
    # Check if outputs are created
    assert os.path.exists(OUTPUT_DIR), "Output directory not created"
    
    expected_files = [
        "metrics.json",
        "classification_report.csv",
        "confusion_matrix.png",
        "feature_importance.png",
        "roc_curve.png",
        "best_rf_model.joblib",
        "preprocessor.joblib",
        "evaluation_summary.md"
    ]
    
    for f in expected_files:
        assert os.path.exists(os.path.join(OUTPUT_DIR, f)), f"Missing expected file: {f}"

def test_metrics_validity():
    import json
    metrics_path = os.path.join(OUTPUT_DIR, "metrics.json")
    assert os.path.exists(metrics_path)
    
    with open(metrics_path, "r") as f:
        metrics = json.load(f)
        
    assert "accuracy" in metrics
    assert "roc_auc" in metrics
    assert metrics["accuracy"] >= 0.0 and metrics["accuracy"] <= 1.0
    assert metrics["roc_auc"] >= 0.0 and metrics["roc_auc"] <= 1.0

def test_model_loadable():
    import joblib
    model_path = os.path.join(OUTPUT_DIR, "best_rf_model.joblib")
    prep_path = os.path.join(OUTPUT_DIR, "preprocessor.joblib")
    
    assert os.path.exists(model_path)
    assert os.path.exists(prep_path)
    
    model = joblib.load(model_path)
    prep = joblib.load(prep_path)
    
    assert isinstance(model, RandomForestClassifier)
    assert isinstance(prep, Pipeline)
