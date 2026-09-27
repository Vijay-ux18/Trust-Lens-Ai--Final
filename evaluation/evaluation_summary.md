# TrustLens AI: ML Evaluation Summary

## A. Dataset Summary
**Dataset source:** Packt Publishing companion materials associated with *Mastering Machine Learning for Penetration Testing*. The original dataset is not redistributed in this repository.
- **Samples**: 138,047
- **Features**: 57 (excluding target)
- **Target Column**: `legitimate`
- **Class Distribution**: 1 (Legitimate) = 41,323, 0 (Malicious) = 96,724

## B. Feature List
- 54 extracted PE structural features used for modeling. Dropped `Name` and `md5` to prevent target leakage.

## C. Preprocessing Method
- **Missing Values**: `SimpleImputer` (median)
- **Scaling**: `StandardScaler`
- Handled seamlessly within an `sklearn.pipeline.Pipeline` to prevent train-test leakage.

## D. Models Evaluated
1. **Baseline**: Logistic Regression
2. **Advanced**: Random Forest Classifier, Gradient Boosting, AdaBoost

## E. Hyperparameters (Tuned)
- {'clf__n_estimators': 150, 'clf__min_samples_split': 2, 'clf__min_samples_leaf': 1, 'clf__max_depth': None}

## F. Cross-Validation Strategy
- The final PE model hyperparameter search used Stratified 3-Fold CV. 
- The final multi-format pipeline used Stratified 5-Fold CV.

## G. Final Test Metrics (Independent PE Holdout = 41,415)
**Submission-facing validation result:** **99.48% independent PE holdout accuracy.**
- **Accuracy**: 99.48%
- **Precision**: 99.10%
- **Recall**: 99.18%
- **F1-Score**: 99.14%
- **ROC-AUC**: 0.9995

## H. Confusion Matrix
- True Negatives: 28,906
- False Positives: 112
- False Negatives: 102
- True Positives: 12,295

## I. Feature Importance
- Top driver: SizeOfStackReserve
- Plot saved as `evaluation/feature_importance.png`

## J. Best Model and Why
- **Random Forest Classifier (150 estimators)** was selected over the baseline because it better captures non-linear relationships within the PE feature space, achieving higher accuracy without severe overfitting due to CV tuning.

## K. Limitations
- Synthetic evasion techniques (like adversarial perturbations) are not represented in the base dataset.

## L. Files Created
- `evaluation/metrics.json`
- `evaluation/training_metrics.json`
- `evaluation/confusion_matrix.png`
- `evaluation/roc_curve.png`
- `evaluation/feature_importance.png`

## M. Command to Reproduce
`python src/btech/pipeline.py`

## N. Trust Score Documentation
The current Trust Score implemented in TrustLens AI uses the probabilistic output of the Random Forest model's benign class prediction:
`Trust Score = P(Legitimate) * 100`
This maps the continuous probabilistic certainty of the model to a 0-100 gauge.
