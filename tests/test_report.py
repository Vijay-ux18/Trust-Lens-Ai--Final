"""
Unit tests for Module 3b: PDF Report Generation Service.
"""

from btech.report import generate_pdf_report


def test_generate_pdf_report() -> None:
    """Verify that report generation compiles a valid PDF byte stream."""
    filename = "test_binary.exe"
    metadata = {
        "file_type": "PDF",
        "SectionsMaxEntropy": 6.8,
        "DllCharacteristics": 0x8140,
        "SizeOfCode": 4096,
        "Machine": 332,
    }
    result = {
        "prediction": "Legitimate",
        "trust_score": 95.5,
        "risk_level": "Low Risk",
        "confidence": 98.2,
    }
    explanation_data = {
        "predicted_class": 1,
        "explanations": [
            {
                "feature_name": "SectionsMaxEntropy",
                "contribution_score": 0.12,
                "influence_direction": "benign",
                "explanation": "Test explanation.",
                "transformed_value": 0.5,
            }
        ],
        "raw_contributions": [
            {"feature": "num__SectionsMaxEntropy", "contribution": 0.12, "value": 0.5}
        ],
    }

    pdf_bytes = generate_pdf_report(filename, metadata, result, explanation_data)

    assert len(pdf_bytes) > 0
    # PDF files must start with the standard PDF header bytes %PDF (hex 25 50 44 46)
    assert pdf_bytes.startswith(b"%PDF")
