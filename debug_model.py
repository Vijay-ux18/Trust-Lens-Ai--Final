import joblib
import pandas as pd
import numpy as np
import sys
sys.path.append('src')

preprocessor = joblib.load("Models/multiformat_preprocessor.joblib")
model = joblib.load("Models/multiformat_model.joblib")

cols = [
    "file_size_kb",
    "entropy",
    "has_executable_code",
    "has_obfuscation",
    "has_network_indicators",
    "has_macros_or_scripts",
    "is_encrypted_or_packed",
    "has_masquerading",
    "metadata_density",
    "suspicious_indicators_count",
]
data = [[0.048828125, 4.701467880199449, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]]
df = pd.DataFrame(data, columns=cols)
X = preprocessor.transform(df)
probs = model.predict_proba(X)[0]
print(f"Probabilities: {probs}")
print(f"Trust Score: {round(probs[1]*100, 2)}")
