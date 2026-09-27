"""
Module 2c: ML Asset Serialization.
Handles saving and loading the model and preprocessing pipeline assets.
"""

import os
from typing import Any, Optional, Tuple

import joblib


def save_assets(
    model: Any,
    preprocessor: Any,
    model_path: str = "models/malware_model.joblib",
    preprocessor_path: str = "models/preprocessor.joblib",
) -> None:
    """
    Serialize the trained model classifier and fitted preprocessor ColumnTransformer to disk.
    """
    joblib.dump(model, model_path)
    joblib.dump(preprocessor, preprocessor_path)


def load_assets(
    model_path: str = "models/malware_model.joblib", preprocessor_path: str = "models/preprocessor.joblib"
) -> Tuple[Optional[Any], Optional[Any]]:
    """
    Deserialize and load the model classifier and preprocessor ColumnTransformer from disk.

    WARNING (Security Boundary): joblib.load can execute arbitrary code during deserialization.
    Ensure model_path and preprocessor_path refer to verified, locally-generated assets.
    """
    model = None
    preprocessor = None

    # Path Security Validation: Block loading of assets outside the workspace root directory
    current_file_dir = os.path.dirname(os.path.realpath(__file__))
    workspace_root = os.path.realpath(os.path.join(current_file_dir, "..", ".."))

    for path_str in [model_path, preprocessor_path]:
        if path_str:
            real_path = os.path.realpath(path_str)
            # Check if path is outside the designated workspace base path
            if os.path.commonpath([real_path, workspace_root]) != workspace_root:

                raise PermissionError(
                    f"Security Block: Model asset path '{path_str}' lies outside "
                    f"the trusted workspace directory '{workspace_root}'."
                )

    if os.path.exists(model_path):
        model = joblib.load(model_path)
    if os.path.exists(preprocessor_path):
        preprocessor = joblib.load(preprocessor_path)

    return model, preprocessor
