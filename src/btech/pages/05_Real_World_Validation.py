"""
TrustLens AI — Real-World Validation
Upload labelled benign/malicious files and evaluate the existing multi-format
model without executing any uploaded file.
"""

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from btech.real_world_evaluation import evaluate_samples  # noqa: E402

st.set_page_config(
    page_title="TrustLens AI - Real-World Validation",
    page_icon="🧪",
    layout="wide",
)

st.markdown(
    """
    <style>
    .title {font-family: Outfit, sans-serif; font-size: 2.2rem; font-weight: 800; color: #f8fafc !important;}
    .desc {color: #94a3b8 !important; margin-bottom: 1.2rem;}
    .notice {padding: 14px 18px; border-radius: 12px; background: #f8fafc;
             border: 1px solid #e2e8f0; margin-bottom: 16px;}
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown("<div class='title'>🧪 Real-World Validation</div>", unsafe_allow_html=True)
st.markdown(
    "<div class='desc'>Evaluate the existing 10-feature multi-format model on "
    "labelled real-world files without executing them.</div>",
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class='notice'>
    <b>Important:</b> This page is an evaluation tool, not a malware execution
    environment. TrustLens performs static feature extraction only. Use files
    from a legally obtained, trusted research corpus and follow its terms of use.
    PE files are intentionally excluded here because they are routed to the
    separate 54-feature PE model.
    </div>
    """,
    unsafe_allow_html=True,
)

col1, col2 = st.columns(2)
with col1:
    benign_files = st.file_uploader(
        "🟢 Benign / legitimate files",
        accept_multiple_files=True,
        type=[
            "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx",
            "pptm", "zip", "rar", "tar", "gz", "apk", "ps1", "js", "py", "bat",
            "vbs", "sh", "cmd", "txt", "csv", "jpg", "jpeg", "png", "gif", "bmp",
        ],
        key="real_world_benign",
    )

with col2:
    malicious_files = st.file_uploader(
        "🔴 Malicious files",
        accept_multiple_files=True,
        type=[
            "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx",
            "pptm", "zip", "rar", "tar", "gz", "apk", "ps1", "js", "py", "bat",
            "vbs", "sh", "cmd", "txt", "csv", "jpg", "jpeg", "png", "gif", "bmp",
        ],
        key="real_world_malicious",
    )

st.caption(
    "For reproducible reporting, record the dataset/corpus name, collection date, "
    "class definition, and sample count alongside the exported results."
)

if st.button("Run Real-World Validation", type="primary", use_container_width=True):
    samples = []
    for uploaded in benign_files or []:
        samples.append(
            {
                "filename": uploaded.name,
                "bytes": uploaded.getvalue(),
                "label": 1,
                "source": "Streamlit labelled upload: benign",
            }
        )
    for uploaded in malicious_files or []:
        samples.append(
            {
                "filename": uploaded.name,
                "bytes": uploaded.getvalue(),
                "label": 0,
                "source": "Streamlit labelled upload: malicious",
            }
        )

    if not samples:
        st.warning("Upload at least one benign or malicious file before evaluation.")
    else:
        try:
            with st.spinner("Performing static analysis and model evaluation..."):
                metrics, results = evaluate_samples(samples)

            st.success(
                f"Evaluation complete: {metrics['samples_evaluated']} files evaluated; "
                f"{metrics['samples_skipped']} skipped."
            )

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Accuracy", f"{metrics['accuracy'] * 100:.2f}%")
            c2.metric("Malicious Recall", f"{metrics['malicious_recall'] * 100:.2f}%")
            c3.metric("Malicious Precision", f"{metrics['malicious_precision'] * 100:.2f}%")
            c4.metric("Malicious F1", f"{metrics['malicious_f1'] * 100:.2f}%")

            if metrics.get("roc_auc") is not None:
                st.metric("ROC-AUC", f"{metrics['roc_auc']:.4f}")

            st.subheader("Confusion Matrix")
            cm = metrics["confusion_matrix"]
            st.dataframe(
                pd.DataFrame(
                    [
                        {"Actual": "Malicious", "Predicted Malicious": cm["tp"], "Predicted Benign": cm["fn"]},
                        {"Actual": "Benign", "Predicted Malicious": cm["fp"], "Predicted Benign": cm["tn"]},
                    ]
                ),
                use_container_width=True,
                hide_index=True,
            )

            st.subheader("File-Level Results")
            display_cols = [
                "filename", "analyzer", "actual_label", "predicted_label",
                "benign_probability", "correct",
            ]
            st.dataframe(
                results[display_cols],
                use_container_width=True,
                hide_index=True,
            )

            if metrics["samples_skipped"]:
                st.warning("Some files were skipped.")
                st.json(metrics["skipped_files"])

            st.download_button(
                "Download Evaluation Results (CSV)",
                data=results.to_csv(index=False).encode("utf-8"),
                file_name="trustlens_real_world_file_results.csv",
                mime="text/csv",
            )
            import json
            st.download_button(
                "Download Evaluation Metrics (JSON)",
                data=json.dumps(metrics, indent=2).encode("utf-8"),
                file_name="trustlens_real_world_metrics.json",
                mime="application/json",
            )

            st.info(
                "Do not report these numbers as universal real-world accuracy. "
                "They describe this particular external evaluation corpus. "
                "The model probability is a classifier score and is not a calibrated real-world probability."
            )

        except Exception as exc:
            st.error(f"Real-world validation could not be completed: {exc}")
