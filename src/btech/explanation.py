"""
Module 3a: Explainable AI (XAI) Engine.
Calculates mathematical local feature contributions from Random Forest decision paths.
Maps feature influences to clear, non-technical explanations for security auditing.
"""

from typing import Any, Dict, List

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# Map PE feature names to readable, non-technical explanations
EXPLANATION_MESSAGES: Dict[str, str] = {
    "num__SectionsMaxEntropy": (
        "High sections entropy (randomness of code blocks) indicates that parts of the file are "
        "packed or encrypted. This is a common evasion technique used by malware authors to hide payloads."
    ),
    "num__DllCharacteristics": (
        "The DllCharacteristics header indicates whether security mitigations like ASLR (Address Space "
        "Layout Randomization) and DEP (Data Execution Prevention) are enabled. Disabling these makes the "
        "binary susceptible to memory corruption exploits."
    ),
    "num__CheckSum": (
        "A checksum of 0 or a header mismatch suggests the binary has been modified after compilation, "
        "which is a standard sign of security evasion or file infection."
    ),
    "num__ImportsNb": (
        "An abnormally low import count suggest that the binary calls minimal system APIs statically. "
        "It likely loads other system functions dynamically at runtime to bypass static antivirus scans."
    ),
    "num__SectionsMeanEntropy": (
        "The overall high entropy of sections indicates that the file as a whole is heavily obfuscated, "
        "compressed, or encrypted to hinder reverse engineering."
    ),
    "num__ResourcesMaxEntropy": (
        "High resource entropy indicates that embedded file assets (e.g. icons, dialogs, configuration data) "
        "contain packed binary blobs, a technique frequently used to drop secondary payloads."
    ),
    "num__Characteristics": (
        "Anomalous file header characteristics indicate that the binary contains non-standard compiler "
        "flags, often seen in custom-written exploits or manual modification stubs."
    ),
    "num__SizeOfImage": (
        "A suspicious virtual image size suggests a discrepancy between the file's raw size on disk "
        "and its memory reservation, indicating code caves or pre-allocation for buffer injection."
    ),
    "num__ImageBase": (
        "A non-standard image base load address indicates compiler manipulation, which is common in "
        "older evasion stubs or manual assembly code."
    ),
    "num__VersionInformationSize": (
        "A missing or tiny version information metadata resource suggests that the executable lacks "
        "valid publisher signatures, company names, or copyright metadata."
    ),
}

DEFAULT_EXPLANATION = "The value of this PE header attribute deviates significantly from standard benign software distributions."


def explain_prediction(
    model: Any, preprocessor: Any, raw_features: Dict[str, Any], target_class: int
) -> Dict[str, Any]:
    """
    Compute local feature contributions for the predicted class by parsing Random Forest tree paths.
    Returns sorted lists of features pushing toward benign (legitimate) or malicious.
    """
    # 1. Transform raw features using preprocessor to match training space
    feat_df = pd.DataFrame([raw_features])
    X_processed = preprocessor.transform(feat_df)

    # Support both DataFrame output (ColumnTransformer with pandas output) and
    # ndarray/sparse output (e.g. StandardScaler used by the multi-format model).
    if hasattr(X_processed, "columns"):
        feature_names = X_processed.columns.tolist()
        x_values = X_processed.to_numpy(dtype=float)
    else:
        if hasattr(X_processed, "toarray"):
            x_values = X_processed.toarray().astype(float)
        else:
            x_values = np.asarray(X_processed, dtype=float)

        if hasattr(preprocessor, "get_feature_names_out"):
            try:
                feature_names = list(preprocessor.get_feature_names_out())
            except Exception:
                feature_names = [f"feature_{i}" for i in range(x_values.shape[1])]
        elif hasattr(preprocessor, "feature_names_in_"):
            feature_names = [str(name) for name in preprocessor.feature_names_in_]
        else:
            feature_names = [f"feature_{i}" for i in range(x_values.shape[1])]

    n_features = len(feature_names)

    contributions = np.zeros(n_features)

    # 2. Check if model supports decision path analysis (Random Forest)
    if isinstance(model, RandomForestClassifier) and hasattr(model, "estimators_"):
        estimators = model.estimators_
        for dt in estimators:
            # Get path nodes traversed by this sample
            # X_processed values must be converted to float numpy array
            x_val = x_values
            path_sparse = dt.decision_path(x_val)
            path_nodes = path_sparse.indices[path_sparse.indptr[0] : path_sparse.indptr[1]]

            # Extract tree structures
            values = dt.tree_.value  # shape (n_nodes, 1, n_classes)
            # Normalise counts at each node to get class probability
            sum_vals = values.sum(axis=2, keepdims=True)
            # Avoid division by zero
            sum_vals[sum_vals == 0] = 1.0
            probs = values / sum_vals

            # Traverse decision path steps
            for i in range(len(path_nodes) - 1):
                node = path_nodes[i]
                next_node = path_nodes[i + 1]
                feat_idx = dt.tree_.feature[node]

                if feat_idx >= 0:  # Leaf split check
                    p_curr = probs[node][0][target_class]
                    p_next = probs[next_node][0][target_class]
                    diff = p_next - p_curr
                    contributions[feat_idx] += diff

        # Average contributions across all trees
        contributions = contributions / len(estimators)
    else:
        # Fallback to feature importance weights relative to standard baseline
        if hasattr(model, "feature_importances_"):
            importances = model.feature_importances_
            # Assume center point is 0 (as scaled)
            # Features far from 0 contribute more
            val_diff = np.abs(x_values[0])
            contributions = importances * val_diff
            if target_class == 0:
                # Invert signs if predicted class is malware (class 0)
                contributions = -contributions

    # 3. Compile top contributing features
    contrib_list = []
    for idx, name in enumerate(feature_names):
        contrib_list.append(
            {
                "feature": name,
                "contribution": float(contributions[idx]),
                "value": float(x_values[0][idx]),
            }
        )

    # Sort contributions by magnitude (absolute value)
    contrib_list.sort(key=lambda x: abs(x["contribution"]), reverse=True)

    # 4. Map top features to non-technical explanations
    explanations: List[Dict[str, Any]] = []
    for c in contrib_list[:3]:  # Top 3 influencers
        feat_name = c["feature"]
        clean_name = feat_name.replace("num__", "").replace("cat__", "")

        # Determine influence direction
        # Positive contribution pushes towards the target_class (1 = legitimate, 0 = malicious)
        if c["contribution"] > 0:
            direction = "benign" if target_class == 1 else "malicious"
        else:
            direction = "malicious" if target_class == 1 else "benign"

        explanation_text = EXPLANATION_MESSAGES.get(feat_name, DEFAULT_EXPLANATION)

        explanations.append(
            {
                "feature_name": clean_name,
                "contribution_score": round(c["contribution"], 4),
                "influence_direction": direction,
                "explanation": explanation_text,
                "transformed_value": round(c["value"], 3),
            }
        )

    return {
        "predicted_class": target_class,
        "explanations": explanations,
        "raw_contributions": contrib_list,
    }
