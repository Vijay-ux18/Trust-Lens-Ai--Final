"""
Module 2: ML Pipeline & Training Orchestrator.
Handles downloading the dataset, preprocessing features, comparing architectures,
tuning hyperparameters, and saving model assets.
"""

import gzip
import json
import os
import shutil

import pandas as pd
import requests
from sklearn.model_selection import StratifiedKFold, train_test_split

from btech.evaluation import compute_evaluation_metrics, evaluate_with_cv
from btech.preprocess import get_preprocessor_pipeline, preprocess_dataset
from btech.save_model import save_assets
from btech.training import train_candidate_models, tune_best_model

DATA_URL = "https://github.com/PacktPublishing/Mastering-Machine-Learning-for-Penetration-Testing/raw/master/Chapter03/MalwareData.csv.gz"
DATA_DIR = "files"
GZ_PATH = os.path.join(DATA_DIR, "MalwareData.csv.gz")
CSV_PATH = os.path.join(DATA_DIR, "MalwareData.csv")
METRICS_PATH = os.path.join(DATA_DIR, "training_metrics.json")

MODEL_PATH = "models/malware_model.joblib"
PREPROCESSOR_PATH = "models/preprocessor.joblib"


def download_dataset() -> None:
    """
    Download the public MalwareData.csv.gz dataset if not already present.
    Supports offline execution if CSV or GZ file is already manually placed.
    """
    os.makedirs(DATA_DIR, exist_ok=True)

    # If raw CSV is already extracted or archive exists, skip download
    if not os.path.exists(CSV_PATH) and not os.path.exists(GZ_PATH):
        print(f"Downloading dataset from {DATA_URL}...")
        try:
            response = requests.get(DATA_URL, stream=True, timeout=60)
            response.raise_for_status()
            with open(GZ_PATH, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print("Download complete.")
        except Exception as e:
            print(f"\n[WARNING] Network download failed: {e}")
            print("To run the training pipeline offline, please manually download the CSV from:")
            print(f"  {DATA_URL}")
            print(f"And place the extracted file at: {CSV_PATH}")
            raise FileNotFoundError(
                f"Raw dataset CSV not found at '{CSV_PATH}', and network download failed."
            ) from e

    if not os.path.exists(CSV_PATH) and os.path.exists(GZ_PATH):
        print("Extracting GZ archive...")
        try:
            with gzip.open(GZ_PATH, "rb") as f_in:
                with open(CSV_PATH, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            print("Extraction complete.")
        except Exception as e:
            print(f"Error during GZ extraction: {e}")
            raise


def load_and_preprocess() -> tuple[pd.DataFrame, pd.Series]:
    """
    Load raw dataset, clean duplicates/contradictions, and separate X and y.
    """
    download_dataset()
    print("Loading CSV dataset...")
    df = pd.read_csv(CSV_PATH, sep="|")
    print(f"Initial raw dataset shape: {df.shape}")
    X, y = preprocess_dataset(df)
    print(f"Features shape: {X.shape}, label distribution: {dict(y.value_counts(normalize=True))}")
    return X, y


def run_pipeline() -> None:
    """
    Orchestrate the entire end-to-end machine learning pipeline:
    1. Load data
    2. Split Train/Test
    3. Fit & Apply Preprocessor ColumnTransformer
    4. Train & Compare candidates (RF, GB, AdaBoost) via CV
    5. Save CV performance scores to files/training_metrics.json
    6. Select & tune best candidate
    7. Evaluate tuned model on holdout set
    8. Save model and preprocessor assets to disk.
    """
    # 1. Load and clean raw feature vectors
    X, y = load_and_preprocess()

    # 2. Stratified Train-Test Split (70:30)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    # 3. Fit ColumnTransformer Preprocessing Pipeline on training data
    print("\nFitting preprocessing pipeline...")
    preprocessor = get_preprocessor_pipeline(X_train)
    X_train_processed = preprocessor.fit_transform(X_train)
    X_test_processed = preprocessor.transform(X_test)

    # 4. Train candidates on preprocessed training split
    print("\nTraining candidate models...")
    fitted_models = train_candidate_models(X_train_processed, y_train)

    # 5. Evaluate candidates using Stratified K-Fold CV (K=5)
    print("\nEvaluating candidates via Stratified 5-Fold Cross-Validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_results = evaluate_with_cv(fitted_models, X_train_processed, y_train, cv)

    # Print CV evaluation comparison matrix
    print("\n--- Cross-Validation Metrics Comparison ---")
    for model_name, metrics in cv_results.items():
        print(
            f"{model_name:18} -> "
            f"Accuracy: {metrics['Accuracy']:.5f}, "
            f"Precision: {metrics['Precision']:.5f}, "
            f"Recall: {metrics['Recall']:.5f}, "
            f"F1-Score: {metrics['F1-Score']:.5f}"
        )

    # Find best model architecture based on mean accuracy
    best_model_name = max(cv_results, key=lambda k: cv_results[k]["Accuracy"])
    print(f"\nBest architecture selected: {best_model_name}")

    # 6. Perform hyperparameter tuning on the best architecture
    print(f"\nTuning hyperparameters on {best_model_name}...")
    tuned_model, best_params = tune_best_model(X_train_processed, y_train, best_model_name, cv)
    print(f"Optimised hyperparameters: {best_params}")

    # Re-fit the best model on full training dataset
    print(f"Fitting tuned {best_model_name} on entire training subset...")
    tuned_model.fit(X_train_processed, y_train)

    # 7. Evaluate tuned model on holdout test set (no fabricated metrics)
    print("\nRunning evaluation on holdout test set...")
    preds = tuned_model.predict(X_test_processed)
    eval_metrics = compute_evaluation_metrics(y_test, preds)

    print("\n--- Final Model Holdout Evaluation ---")
    print(f"Test Accuracy: {eval_metrics['accuracy']:.5f}")
    print(f"True Positive Rate (TPR): {eval_metrics['tpr']:.5f}")
    print(f"True Negative Rate (TNR): {eval_metrics['tnr']:.5f}")
    print(f"False Positive Rate (FPR): {eval_metrics['fpr']:.5f} (Security Evasion Risk)")
    print(f"False Negative Rate (FNR): {eval_metrics['fnr']:.5f} (Infection Slip Risk)")

    # Save training history and evaluation metrics to files/training_metrics.json
    metrics_summary = {
        "cross_validation": cv_results,
        "best_model": best_model_name,
        "best_params": best_params,
        "holdout_test": eval_metrics,
    }

    with open(METRICS_PATH, "w") as f:
        json.dump(metrics_summary, f, indent=2)
    print(f"Training metrics logged to '{METRICS_PATH}'.")

    # 8. Serialize pipeline assets
    print(f"\nSerialising model to '{MODEL_PATH}'...")
    print(f"Serialising preprocessor to '{PREPROCESSOR_PATH}'...")
    save_assets(tuned_model, preprocessor, MODEL_PATH, PREPROCESSOR_PATH)
    print("Serialization complete.")


if __name__ == "__main__":
    run_pipeline()
