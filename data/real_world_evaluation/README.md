# External Real-World PDF Benchmark

TrustLens includes a PDF-specific benchmark model trained/evaluated on the labelled CIC-Evasive-PDFMal2022 feature table. The benchmark uses a 10-feature adapter that can also be extracted from raw PDF bytes, allowing the same feature schema to be used for file-level PDF prediction.

This is a **PDF-specific external benchmark** and is not a claim of universal accuracy across all TrustLens-supported formats. Separately, the project reports **99.48% accuracy on the independent 41,415-sample PE holdout validation set**.

The CSV is intentionally not bundled. Obtain it from the official CIC/UNB source, cite the dataset/paper, and run:

```bash
python run_external_pdf_benchmark.py /path/to/PDFMalware2022.csv
```


## Submission-safe protocol
Use independently labelled raw files, preferably as a balanced cross-format corpus within a 400 MB test-data limit. Keep raw samples outside the submission ZIP. Use `evaluation_manifest_template.csv` to record SHA-256, provenance, permission/licence and ground truth. The resulting accuracy applies only to that tested corpus.
