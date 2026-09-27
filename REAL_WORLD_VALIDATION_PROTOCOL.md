# TrustLens AI — Real-World Validation Protocol

## Purpose
This protocol defines how to obtain a defensible real-file validation result for TrustLens AI. It is an evaluation protocol, not an accuracy claim.

## Test corpus
Use independently labelled, legally obtainable raw files. The recommended practical submission experiment is a balanced, cross-format corpus within the available test-data limit (up to 400 MB total). Record the provenance and licence/permission for every source.

Supported families should be represented where independently labelled raw files are available: PE/executable, PDF, Office/OLE, archive, script, image and other formats accepted by the application. Do not force unsupported formats into the experiment.

## Ground truth
Ground truth must come from the dataset/provider or another independent authority. Do not infer labels from TrustLens predictions.

## Safety
- Never execute test files.
- Perform static analysis only.
- Keep suspicious raw samples outside the project submission ZIP.
- Store SHA-256 hashes and provenance in the evaluation manifest.

## Metrics
Report accuracy, precision, recall, F1, confusion matrix and (when probabilities are valid for the complete evaluated set) ROC-AUC. Also report sample counts, skipped files and errors.

## Claim boundary
A measured result is valid only for the exact independent corpus tested. It must not be described as universal accuracy across all present or future real-world threats.

## Reproducibility
The repository provides `run_real_world_eval.py` and `src/btech/real_world_evaluation.py`. Put labelled files in:

```text
data/real_world_dataset/
    benign/
    malicious/
```

Then run:

```bash
PYTHONPATH=src python run_real_world_eval.py
```

The generated evidence contains per-file SHA-256, ground truth, prediction and aggregate metrics.
