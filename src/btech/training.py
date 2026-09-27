"""
Module 2a: ML Model Training.
Defines functions to train baseline candidate classifiers and run hyperparameter tuning.
"""

from typing import Any, Dict

from sklearn.ensemble import AdaBoostClassifier, GradientBoostingClassifier, RandomForestClassifier
from sklearn.model_selection import RandomizedSearchCV


def train_candidate_models(X_train: Any, y_train: Any) -> Dict[str, Any]:
    """
    Train and return the baseline classifiers: Random Forest, AdaBoost, and Gradient Boosting.
    """
    models = {
        "Random Forest": RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1),
        "AdaBoost": AdaBoostClassifier(n_estimators=50, random_state=42),
        "Gradient Boosting": GradientBoostingClassifier(n_estimators=50, random_state=42),
    }

    for name, model in models.items():
        model.fit(X_train, y_train)

    return models


def tune_best_model(X_train: Any, y_train: Any, model_name: str, cv: Any) -> Any:
    """
    Perform RandomizedSearchCV on the selected best model architecture.
    """
    if model_name == "Random Forest":
        base_clf = RandomForestClassifier(random_state=42, n_jobs=-1)
        param_dist = {
            "n_estimators": [50, 100, 150],
            "max_depth": [10, 20, None],
            "min_samples_split": [2, 5],
            "min_samples_leaf": [1, 2],
        }
    elif model_name == "Gradient Boosting":
        base_clf = GradientBoostingClassifier(random_state=42)
        param_dist = {
            "n_estimators": [50, 100],
            "learning_rate": [0.05, 0.1, 0.2],
            "max_depth": [3, 5, 8],
        }
    else:
        # Default fallback
        base_clf = RandomForestClassifier(random_state=42, n_jobs=-1)
        param_dist = {"n_estimators": [100]}

    search = RandomizedSearchCV(
        base_clf,
        param_distributions=param_dist,
        n_iter=5,
        cv=cv,
        scoring="accuracy",
        random_state=42,
        n_jobs=-1,
    )
    search.fit(X_train, y_train)
    return search.best_estimator_, search.best_params_
