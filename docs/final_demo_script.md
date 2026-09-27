# Demonstration Script
**2-Minute Version:** Upload sample file -> Show zero-execution static analysis -> Point out Trust Score -> Show Explainability.
**5-Minute Version:** Above + Discuss PE empirical model vs Multi-format proof of concept -> Show MITRE ATT&CK mapping.
**10-Minute Version:** Above + Dive into Feature extraction code -> Run pytest -> Explain Random Forest hyperparameter tuning.
*Fallback:* If ML fails, heuristic test/mock scenario only activates automatically.


### Real-World Validation Demo (optional final-review enhancement)
1. Open **🧪 Real-World Validation** from the Streamlit sidebar.
2. Upload independently labelled benign files in the left uploader and malicious files in the right uploader.
3. Click **Run Real-World Validation**.
4. Explain that TrustLens performs static feature extraction only and never executes the uploaded files.
5. Show Accuracy, Malicious Recall, Malicious Precision, Malicious F1 and ROC-AUC (when both classes are present).
6. Emphasize that the existing **99.80% multi-format result is synthetic proof-of-concept performance**, while the displayed real-world metrics are calculated from the actual labelled corpus used in the demonstration.
