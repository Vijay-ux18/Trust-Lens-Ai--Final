"""
Unit and integration tests for Module 3: Inference & Prediction Service.
Supports the multi-format pipeline and plugin structure.
"""

import pytest

from btech.predict import TrustLensPredictor


def test_predictor_explanations_triggers() -> None:
    """Verify that rule-based alerts trigger correctly based on common feature values."""
    predictor = TrustLensPredictor()

    # 1. Test clean features (should trigger no alerts)
    clean_features = {
        "file_size_kb": 10.0,
        "entropy": 3.2,
        "has_executable_code": 0.0,
        "has_obfuscation": 0.0,
        "has_network_indicators": 0.0,
        "has_macros_or_scripts": 0.0,
        "is_encrypted_or_packed": 0.0,
        "has_masquerading": 0.0,
        "metadata_density": 0.5,
        "suspicious_indicators_count": 0.0,
    }
    alerts, recs = predictor._generate_explanations_and_recs(clean_features)
    assert len(alerts) == 0

    # 2. Test high entropy trigger
    dirty_features1 = clean_features.copy()
    dirty_features1["has_obfuscation"] = 1.0
    alerts1, recs1 = predictor._generate_explanations_and_recs(dirty_features1)
    assert len(alerts1) == 1
    assert "obfuscation" in alerts1[0].lower()

    # 3. Test masquerading trigger
    dirty_features2 = clean_features.copy()
    dirty_features2["has_masquerading"] = 1.0
    alerts2, recs2 = predictor._generate_explanations_and_recs(dirty_features2)
    assert len(alerts2) == 1
    assert "masquerading" in alerts2[0].lower()


def test_predict_file_simulated_mode() -> None:
    """Verify that prediction runs successfully on generic text files using a test/mock scenario only — not production inference."""
    predictor = TrustLensPredictor(
        model_path="nonexistent.joblib", preprocessor_path="nonexistent.joblib"
    )
    predictor.load_assets()
    assert not predictor.is_loaded

    # Create dummy bytes resembling text
    dummy_text = b"dummy text not a PE file"

    import pytest
    # We removed mock mode and expect a RuntimeError instead
    with pytest.raises(RuntimeError, match="ML Models are not loaded"):
        predictor.predict_file(dummy_text, filename="doc.txt")
    # No results returned because it raises an error
