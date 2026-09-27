"""
Real-world validation utilities for TrustLens AI.

This module evaluates the existing 10-feature multi-format Random Forest on
user-supplied, labelled files. Files are analysed statically only; they are
never executed.

Expected directory layout for CLI evaluation:
data/real_world_dataset/
├── benign/
└── malicious/

The multi-format model is evaluated on non-PE formats. PE files are reported
as skipped because TrustLens routes them to its separate 54-feature PE model.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)

from btech.analyzers.base import BaseAnalyzer
from btech.analyzers.executable import ExecutableAnalyzer
from btech.analyzers.archive import ArchiveAnalyzer
from btech.analyzers.image import ImageAnalyzer
from btech.analyzers.normalization import FeatureNormalizer
from btech.analyzers.office import DocAnalyzer, ExcelAnalyzer, PowerPointAnalyzer
from btech.analyzers.pdf import PDFAnalyzer
from btech.analyzers.script import ScriptAnalyzer

ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = ROOT / "Models" / "multiformat_model.joblib"
PREPROCESSOR_PATH = ROOT / "Models" / "multiformat_preprocessor.joblib"
DEFAULT_OUTPUT_DIR = ROOT / "data" / "real_world_evaluation"

SUPPORTED_EXTENSIONS = {
    "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm",
    "ppt", "pptx", "pptm", "zip", "rar", "tar", "gz", "apk",
    "ps1", "js", "py", "bat", "vbs", "sh", "cmd", "txt", "csv",
    "jpg", "jpeg", "png", "gif", "bmp",
}

ANALYZERS: list[BaseAnalyzer] = [
    ExecutableAnalyzer(),
    PDFAnalyzer(),
    DocAnalyzer(),
    ExcelAnalyzer(),
    PowerPointAnalyzer(),
    ArchiveAnalyzer(),
    ScriptAnalyzer(),
    ImageAnalyzer(),
]


def _select_analyzer(filename: str, file_bytes: bytes) -> BaseAnalyzer | None:
    ext = Path(filename).suffix.lower().lstrip(".")
    for analyzer in ANALYZERS:
        if analyzer.can_handle(ext, file_bytes):
            return analyzer
    return None


def _is_pe_analyzer(analyzer: BaseAnalyzer) -> bool:
    return isinstance(analyzer, ExecutableAnalyzer)


def _common_features(filename: str, file_bytes: bytes) -> tuple[dict[str, float], str]:
    analyzer = _select_analyzer(filename, file_bytes)
    if analyzer is None:
        raise ValueError("Unsupported file format")
    if _is_pe_analyzer(analyzer):
        raise ValueError("PE file: routed to the separate 54-feature PE model")
    features = analyzer.extract_features(file_bytes, filename)
    common = FeatureNormalizer.map_to_common_vector(features, filename)
    return common, analyzer.__class__.__name__


def evaluate_samples(
    samples: Sequence[Mapping[str, Any]],
    model_path: str | os.PathLike[str] = MODEL_PATH,
    preprocessor_path: str | os.PathLike[str] = PREPROCESSOR_PATH,
) -> tuple[dict[str, Any], pd.DataFrame]:
    """
    Evaluate labelled real-world files.

    Each sample must contain:
      filename: str
      bytes: bytes
      label: 0 for malicious, 1 for benign
      source: optional provenance string
    """
    model = joblib.load(model_path)
    preprocessor = joblib.load(preprocessor_path)

    rows: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []

    for sample in samples:
        filename = str(sample["filename"])
        raw = bytes(sample["bytes"])
        label = int(sample["label"])

        if label not in (0, 1):
            raise ValueError(f"Invalid label for {filename}: use 0=malicious or 1=benign")

        try:
            common, analyzer_name = _common_features(filename, raw)
        except ValueError as exc:
            skipped.append({"filename": filename, "reason": str(exc)})
            continue
        except Exception as exc:
            skipped.append({"filename": filename, "reason": f"analysis error: {exc}"})
            continue

        rows.append(
            {
                "filename": filename,
                "label": label,
                "source": str(sample.get("source", "user-supplied")),
                "analyzer": analyzer_name,
                **common,
            }
        )

    if not rows:
        raise ValueError(
            "No evaluable non-PE files were supplied. Add supported labelled "
            "real-world files; PE files are evaluated by the separate PE model."
        )

    feature_names = FeatureNormalizer.get_feature_list()
    X = pd.DataFrame(rows)[feature_names]
    y = pd.Series([row["label"] for row in rows], name="label")

    X_scaled = preprocessor.transform(X)
    predictions = model.predict(X_scaled).astype(int)
    probabilities = model.predict_proba(X_scaled)[:, 1]

    cm = confusion_matrix(y, predictions, labels=[0, 1])
    # With labels=[0, 1], the matrix is [[TP, FN], [FP, TN]] because
    # TrustLens defines malicious (0) as the positive/security-critical class.
    tp, fn, fp, tn = (int(v) for v in cm.ravel())

    malicious_precision = precision_score(y, predictions, pos_label=0, zero_division=0)
    malicious_recall = recall_score(y, predictions, pos_label=0, zero_division=0)
    malicious_f1 = f1_score(y, predictions, pos_label=0, zero_division=0)

    metrics: dict[str, Any] = {
        "evaluation_type": "real_world_external_validation",
        "model": "multiformat_model.joblib",
        "label_definition": {
            "0": "malicious",
            "1": "benign",
        },
        "samples_submitted": len(samples),
        "samples_evaluated": len(rows),
        "samples_skipped": len(skipped),
        "skipped_files": skipped,
        "accuracy": float(accuracy_score(y, predictions)),
        "precision": float(precision_score(y, predictions, zero_division=0)),
        "recall": float(recall_score(y, predictions, zero_division=0)),
        "f1": float(f1_score(y, predictions, zero_division=0)),
        "malicious_precision": float(malicious_precision),
        "malicious_recall": float(malicious_recall),
        "malicious_f1": float(malicious_f1),
        "confusion_matrix": {
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
        },
        "classification_report": classification_report(
            y,
            predictions,
            labels=[0, 1],
            target_names=["malicious", "benign"],
            output_dict=True,
            zero_division=0,
        ),
        "provenance": sorted(set(row["source"] for row in rows)),
        "note": (
            "This is an external real-world validation result, not a replacement "
            "for the synthetic training/holdout experiment. PE files are excluded "
            "because TrustLens routes PE files to the separate 54-feature model."
        ),
    }

    if len(np.unique(y)) == 2:
        metrics["roc_auc"] = float(roc_auc_score(y, probabilities))
    else:
        metrics["roc_auc"] = None
        metrics["roc_auc_note"] = "ROC-AUC requires both benign and malicious classes."

    result_df = pd.DataFrame(rows)
    result_df["prediction"] = predictions
    result_df["benign_probability"] = probabilities
    result_df["predicted_label"] = np.where(predictions == 1, "benign", "malicious")
    result_df["actual_label"] = np.where(y.to_numpy() == 1, "benign", "malicious")
    result_df["correct"] = predictions == y.to_numpy()

    return metrics, result_df


def evaluate_directory(
    dataset_dir: str | os.PathLike[str],
    output_dir: str | os.PathLike[str] = DEFAULT_OUTPUT_DIR,
) -> dict[str, Any]:
    """Evaluate data/real_world_dataset/{benign,malicious} without executing files."""
    dataset = Path(dataset_dir)
    samples: list[dict[str, Any]] = []

    for class_name, label in (("malicious", 0), ("benign", 1)):
        class_dir = dataset / class_name
        if not class_dir.exists():
            continue
        for path in sorted(p for p in class_dir.rglob("*") if p.is_file()):
            samples.append(
                {
                    "filename": path.name,
                    "bytes": path.read_bytes(),
                    "label": label,
                    "source": f"directory:{class_name}",
                }
            )

    metrics, results = evaluate_samples(samples)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    (out / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    results.to_csv(out / "file_results.csv", index=False)
    return metrics
