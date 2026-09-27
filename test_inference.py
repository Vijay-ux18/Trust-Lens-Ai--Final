from btech.predict import TrustLensPredictor
predictor = TrustLensPredictor()
predictor.load_assets()
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
    "file_format": "Test Document"
}
dirty_features = {
    "file_size_kb": 10.0,
    "entropy": 7.9,
    "has_executable_code": 1.0,
    "has_obfuscation": 1.0,
    "has_network_indicators": 1.0,
    "has_macros_or_scripts": 1.0,
    "is_encrypted_or_packed": 1.0,
    "has_masquerading": 1.0,
    "metadata_density": 0.1,
    "suspicious_indicators_count": 5.0,
    "file_format": "Executable"
}
import pandas as pd
from btech.analyzers.normalization import FeatureNormalizer
ordered_cols = FeatureNormalizer.get_feature_list()

df_clean = pd.DataFrame([clean_features])[ordered_cols]
X_clean = predictor.preprocessor.transform(df_clean)
probs_clean = predictor.model.predict_proba(X_clean)[0]
print("Clean probs:", probs_clean)

df_dirty = pd.DataFrame([dirty_features])[ordered_cols]
X_dirty = predictor.preprocessor.transform(df_dirty)
probs_dirty = predictor.model.predict_proba(X_dirty)[0]
print("Dirty probs:", probs_dirty)
