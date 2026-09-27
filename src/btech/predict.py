"""
Module 3: Inference & Prediction Service.
Loads the serialized multi-format Random Forest model and preprocessor,
resolves file types using plugin analyzers, normalizes features,
and yields the Trust Score, Risk Category, and explanations.
"""

import math
import os
from typing import Any, Dict, List, Optional, Tuple

import joblib
import pandas as pd

from btech.analyzers.archive import ArchiveAnalyzer

# Import plugin analyzers
from btech.analyzers.base import BaseAnalyzer
from btech.analyzers.executable import ExecutableAnalyzer
from btech.analyzers.image import ImageAnalyzer
from btech.analyzers.normalization import FeatureNormalizer
from btech.analyzers.office import DocAnalyzer, ExcelAnalyzer, PowerPointAnalyzer
from btech.analyzers.pdf import PDFAnalyzer
from btech.analyzers.script import ScriptAnalyzer
from btech.explanation import explain_prediction

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "Models", "multiformat_model.joblib")
PREPROCESSOR_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "Models", "multiformat_preprocessor.joblib")


class TrustLensPredictor:
    """
    Predictor service loading serialized multi-format models to perform file safety diagnostics.
    """

    def __init__(
        self, model_path: str = MODEL_PATH, preprocessor_path: str = PREPROCESSOR_PATH
    ) -> None:
        self.model_path = model_path
        self.preprocessor_path = preprocessor_path
        self.model: Any = None
        self.preprocessor: Any = None
        self.is_loaded = False

        self.pe_model_path = os.path.join(os.path.dirname(__file__), "..", "..", "Models", "malware_model.joblib")
        self.pe_preprocessor_path = os.path.join(os.path.dirname(__file__), "..", "..", "Models", "preprocessor.joblib")
        self.pe_model: Any = None
        self.pe_preprocessor: Any = None
        self.is_pe_loaded = False

        # Register plugin analyzers dynamically (Plugin Architecture)
        self.analyzers: List[BaseAnalyzer] = [
            ExecutableAnalyzer(),
            PDFAnalyzer(),
            DocAnalyzer(),
            ExcelAnalyzer(),
            PowerPointAnalyzer(),
            ArchiveAnalyzer(),
            ScriptAnalyzer(),
            ImageAnalyzer(),
        ]

    def load_assets(self) -> None:
        """
        Load the multi-format and PE-only models and preprocessors from disk with path validation.
        """
        current_file_dir = os.path.realpath(os.path.dirname(__file__))
        workspace_root = os.path.realpath(os.path.join(current_file_dir, "..", ".."))

        # Path validation security check
        for path_str in [
            self.model_path,
            self.preprocessor_path,
            self.pe_model_path,
            self.pe_preprocessor_path,
        ]:
            if path_str:
                abs_path = os.path.realpath(path_str)
                if os.path.commonpath([abs_path, workspace_root]) != workspace_root:
                    raise PermissionError(
                        "Security Block: Loading model asset outside workspace is forbidden."
                    )

        model = None
        preprocessor = None
        if os.path.exists(self.model_path):
            model = joblib.load(self.model_path)
        if os.path.exists(self.preprocessor_path):
            preprocessor = joblib.load(self.preprocessor_path)

        if model is not None and preprocessor is not None:
            self.model = model
            self.preprocessor = preprocessor
            self.is_loaded = True
        else:
            self.is_loaded = False

        pe_model = None
        pe_preprocessor = None
        if os.path.exists(self.pe_model_path):
            pe_model = joblib.load(self.pe_model_path)
        if os.path.exists(self.pe_preprocessor_path):
            pe_preprocessor = joblib.load(self.pe_preprocessor_path)

        if pe_model is not None and pe_preprocessor is not None:
            self.pe_model = pe_model
            self.pe_preprocessor = pe_preprocessor
            self.is_pe_loaded = True
        else:
            self.is_pe_loaded = False

    def predict_file(self, file_bytes: bytes, filename: str = "") -> Dict[str, Any]:
        """
        Identify the matching analyzer, extract features, normalize them, and predict threat scores.
        """
        ext = filename.split(".")[-1].lower() if "." in filename else ""

        # Phase 1: Signature Mismatch Check
        sig = file_bytes[:10] if len(file_bytes) >= 10 else file_bytes
        detected_type = "UNKNOWN"
        if sig.startswith(b"%PDF-"):
            detected_type = "pdf"
        elif sig.startswith(b"PK\x03\x04"):
            detected_type = "zip/ooxml"
        elif sig.startswith(b"MZ"):
            detected_type = "pe"
        elif sig.startswith(b"\x89PNG\r\n\x1a\n"):
            detected_type = "png"
        elif sig.startswith(b"\xff\xd8"):
            detected_type = "jpeg"
        elif sig.startswith(b"GIF87a") or sig.startswith(b"GIF89a"):
            detected_type = "gif"
        elif sig.startswith(b"Rar!"):
            detected_type = "rar"
            
        extension_mismatch = False
        mismatch_reason = ""
        
        if ext == "txt" and detected_type in ["pdf", "pe", "zip/ooxml"]:
            extension_mismatch = True
            mismatch_reason = f"File content/signature does not match declared extension"
        elif ext in ["pdf"] and detected_type not in ["pdf", "UNKNOWN"]:
            extension_mismatch = True
            mismatch_reason = f"File content/signature does not match declared extension"
        elif ext in ["exe", "dll", "sys"] and detected_type not in ["pe", "UNKNOWN"]:
            extension_mismatch = True
            mismatch_reason = f"File content/signature does not match declared extension"
        elif ext in ["zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm"] and detected_type not in ["zip/ooxml", "UNKNOWN"]:
            extension_mismatch = True
            mismatch_reason = f"File content/signature does not match declared extension"
        elif ext in ["png"] and detected_type not in ["png", "UNKNOWN"]:
            extension_mismatch = True
            mismatch_reason = f"File content/signature does not match declared extension"

        # Find matching plugin analyzer (Plugin Architecture check)
        selected_analyzer: Optional[BaseAnalyzer] = None
        for analyzer in self.analyzers:
            if analyzer.can_handle(ext, file_bytes):
                selected_analyzer = analyzer
                break

        if not selected_analyzer:
            return {
                "prediction": 0,
                "trust_score": 0.0,
                "risk_percentage": 0.0,
                "risk_level": "UNSUPPORTED",
                "risk_category": "Unsupported",
                "reasons": ["Unsupported file type — TrustLens cannot perform reliable static analysis for this format."],
                "features": {},
                "confidence": 0.0,
                "recommendation": "File format not supported by any active analyzers.",
                "is_mock": False,
                "explanation_data": {},
            }
            
        try:
            features = selected_analyzer.extract_features(file_bytes, filename)
        except Exception as e:
            # Fallback generic text/binary parser
            entropy = 0.0
            if file_bytes:
                from collections import Counter

                counter = Counter(file_bytes)
                length = len(file_bytes)
                for count in counter.values():
                    p_x = count / length
                    entropy -= p_x * math.log2(p_x)
            features = {
                "file_size_kb": len(file_bytes) / 1024,
                "entropy": entropy,
                "file_format": f"{ext.upper()} Document" if ext else "Binary Block",
            }
            
        features["extension_mismatch"] = extension_mismatch
        features["mismatch_reason"] = mismatch_reason
        features["declared_ext"] = ext
        features["detected_type"] = detected_type

        # Normalize format-specific features to the 10-D Common Feature Vector
        common_features = FeatureNormalizer.map_to_common_vector(features, filename)

        # Generate explanations & recommendations based on common features
        rule_explanations, recommendations = self._generate_explanations_and_recs(common_features)

        # Determine if we should route to PE-only deep classifier
        is_pe = isinstance(selected_analyzer, ExecutableAnalyzer) and "parsing_error" not in features

        if is_pe and self.is_pe_loaded:
            # Route to PE Model
            feat_df = pd.DataFrame([features])
            ordered_cols = list(self.pe_preprocessor.feature_names_in_)
            feat_df = feat_df[ordered_cols]

            X_scaled = self.pe_preprocessor.transform(feat_df)

            probs = self.pe_model.predict_proba(X_scaled)[0]
            prediction = int(self.pe_model.predict(X_scaled)[0])
            trust_score = round(float(probs[1]) * 100, 2)
            is_mock = False
        else:
            # Fallback or route to Multi-Format Model
            if not self.is_loaded:
                raise RuntimeError("ML Models are not loaded. Cannot perform prediction.")
            else:
                # Preprocess features using standard scaler
                feat_df = pd.DataFrame([common_features])
                ordered_cols = FeatureNormalizer.get_feature_list()
                feat_df = feat_df[ordered_cols]

                X_scaled = self.preprocessor.transform(feat_df)

                # Predict probability
                probs = self.model.predict_proba(X_scaled)[0]
                prediction = int(self.model.predict(X_scaled)[0])
                trust_score = round(float(probs[1]) * 100, 2)
                
                # Heuristic calibration: Prevent False Positives on completely clean files
                # The model may penalize benign files heavily if they lack metadata (e.g. metadata_density = 0).
                # If there are absolutely 0 suspicious indicators and 0 executable code, it is benign.
                if common_features.get("suspicious_indicators_count", 0.0) == 0.0 and common_features.get("has_executable_code", 0.0) == 0.0:
                    if trust_score < 95.0:
                        trust_score = min(98.5, trust_score + 30.0)
                        
                is_mock = False

        # Map Trust Score to Risk Category (Safe, Low, Medium, High, Critical)
        risk_percentage = round(100.0 - trust_score, 2)
        if trust_score >= 95.0:
            risk_category = "Safe"
        elif trust_score >= 80.0:
            risk_category = "Low"
        elif trust_score >= 50.0:
            risk_category = "Medium"
        elif trust_score >= 20.0:
            risk_category = "High"
        else:
            risk_category = "Critical"

        # Generate model-derived local XAI contributions for the live inference path.
        # This replaces placeholder frontend values with actual Random Forest decision-path
        # contributions for both the PE and multi-format classifiers.
        if is_pe and self.is_pe_loaded:
            explanation_data = explain_prediction(
                self.pe_model, self.pe_preprocessor, features, target_class=prediction
            )
        else:
            explanation_data = explain_prediction(
                self.model, self.preprocessor, common_features, target_class=prediction
            )

        # Explanation generation (max 4 lines)
        if risk_category in ["Safe", "Low"]:
            short_explanation = (
                f"The target file displays a high trust profile of {trust_score}%. "
                "No indicators of packaging, active VBA macro scripts, masquerading signatures, "
                "or security bypass techniques were flagged in the file structure."
            )
        elif risk_category == "Medium":
            short_explanation = (
                f"The target file is profiled at Medium Risk. Missing memory mitigations or low-level "
                "obfuscation signals are active. Verify source credentials before loading."
            )
        else:
            short_explanation = (
                f"The file triggers a {risk_category} risk alert. "
                "High entropy structures, executable overlays, or masqueraded file extension headers "
                "suggest signature evasion attempts."
            )

        # Generate format-specific list of reasons matching the requested style
        reasons = []
        file_format = features.get("file_format", "")
        entropy = float(features.get("entropy", 0.0))

        # 1. Masquerading check
        if common_features.get("has_masquerading", 0.0) == 1.0:
            if features.get("extension_mismatch"):
                reasons.append(f"Extension mismatch detected\nDeclared type: {ext.upper()}\nDetected type: {detected_type.upper()}")
            else:
                reasons.append("Binary masquerading detected")

        # 2. Obfuscation check
        if common_features.get("has_obfuscation", 0.0) == 1.0:
            reasons.append("Code obfuscation or packing detected")

        # 3. Format-specific reasons
        if file_format == "PDF Document":
            js = features.get("js_count", 0)
            uri = features.get("uri_count", 0)
            enc = features.get("is_encrypted", 0)
            meta = features.get("metadata_count", 0)

            if js > 0:
                reasons.append("JavaScript detected")
            if uri > 0:
                reasons.append(f"Contains {uri} embedded hyperlinks")
            if enc == 1:
                reasons.append("PDF is encrypted")
            if meta == 0:
                reasons.append("Unknown author")
            elif entropy > 7.2:
                reasons.append("Suspicious metadata")

        elif "Word" in file_format or "Excel" in file_format or "PowerPoint" in file_format:
            mac = features.get("has_macros", 0)
            lnk = features.get("link_count", 0)
            emb = features.get("embedded_count", 0)
            hid = features.get("hidden_sheets", 0)

            if mac == 1:
                reasons.append("Contains active VBA macro scripts")
            if lnk > 0:
                reasons.append(f"Contains {lnk} embedded hyperlinks")
            if emb > 0:
                reasons.append(f"Contains {emb} embedded OLE objects")
            if hid > 0:
                reasons.append(f"Contains {hid} hidden worksheets")

        elif "Script" in file_format:
            cmds = features.get("suspicious_commands_count", 0)
            obf = features.get("obfuscation_score", 0)
            b64 = features.get("has_encoded_payload", 0)

            if cmds > 0:
                reasons.append(f"Contains {cmds} suspicious command keywords")
            if obf > 3:
                reasons.append("High code obfuscation score")
            if b64 == 1:
                reasons.append("Large Base64/encoded payload block found")

        elif "Archive" in file_format:
            nest = features.get("nested_archives", 0)
            execs = features.get("executable_contents", 0)
            scripts = features.get("script_contents", 0)
            enc = features.get("is_encrypted", 0)
            susp = features.get("nested_suspicious_file_count", 0)
            susp_paths = features.get("suspicious_nested_paths", [])
            limited = features.get("archive_analysis_limited", 0)

            if execs > 0:
                reasons.append(f"Contains {execs} nested executables")
            if scripts > 0:
                reasons.append(f"Contains {scripts} nested scripts")
            if nest > 0:
                reasons.append(f"Contains {nest} nested archives")
            if enc == 1:
                reasons.append("Archive is password protected")
            if susp > 0:
                if susp_paths:
                    for path in susp_paths[:3]:
                        reasons.append(f"Suspicious content detected in nested archive: {path}")
                    if len(susp_paths) > 3:
                        reasons.append(f"...and {len(susp_paths) - 3} more suspicious nested files")
                else:
                    reasons.append(f"Nested archive analyzed\nSuspicious nested files: {susp}")
            if limited == 1:
                reasons.append("Maximum nested archive analysis depth reached")

        elif "PDF" in file_format:
            js = features.get("js_count", 0)
            if js > 0:
                reasons.append("JavaScript detected")
            if features.get("uri_count", 0) > 0:
                reasons.append("Contains network URLs/hyperlinks")
            if features.get("embed_count", 0) > 0:
                reasons.append("Contains embedded files/objects")
            if features.get("is_encrypted", 0) == 1:
                reasons.append("Document encryption detected")
            if features.get("metadata_count", 0) == 0:
                reasons.append("Unknown author")

        elif "Image" in file_format:
            meta = features.get("metadata_count", 0)
            if meta == 0:
                reasons.append("EXIF metadata is empty")
            elif entropy > 7.5:
                reasons.append("High byte randomness (potential polyglot payload)")

        elif "Executable" in file_format or "Library" in file_format:
            if features.get("parsing_error"):
                reasons.append("Malformed executable or invalid PE header")
            else:
                reasons.append("Valid executable structure detected")
                
            ent = features.get("SectionsMaxEntropy", 0.0)
            chk = features.get("CheckSum", 1)
            dll = features.get("DllCharacteristics", 0)
            has_aslr = bool(dll & 0x0040)
            has_dep = bool(dll & 0x0100)

            if ent > 7.2:
                reasons.append(f"High section entropy ({ent:.2f})")
            if chk == 0:
                reasons.append("PE checksum is missing or invalid")
            if not has_aslr or not has_dep:
                reasons.append("Compile-time mitigations (DEP/ASLR) are disabled")

        if not reasons and trust_score < 95.0:
            reasons.append("General security profile anomalies identified")

        # Standardized Recommendation
        if trust_score >= 80.0:
            recommendation = "No significant static indicators detected; further organizational security controls are recommended."
        elif trust_score >= 50.0:
            recommendation = "Verify compiler and source credentials before loading."
        else:
            recommendation = "Do NOT open this file."

        result = {
            "prediction": "Legitimate" if prediction == 1 else "Malicious",
            "trust_score": trust_score,
            "risk_percentage": risk_percentage,
            "risk_level": risk_category.upper(),
            "risk_category": risk_category,
            "confidence": round(float(max(probs)) * 100, 2),
            "reasons": reasons,
            "recommendation": recommendation,
            "rule_explanations": rule_explanations,
            "recommendations": recommendations,
            "short_explanation": short_explanation,
            "features": features,
            "common_features": common_features,
            "is_mock": is_mock,
            "explanation_data": explanation_data,
        }
        return result

    def _generate_explanations_and_recs(
        self, common_features: Dict[str, Any]
    ) -> Tuple[List[str], List[str]]:
        alerts = []
        recs = []

        if common_features.get("has_masquerading", 0.0) == 1.0:
            alerts.append(
                "Binary masquerading detected: Mismatch between file extension and magic signature headers."
            )
            recs.append("🚨 DO NOT OPEN: Quarantined as extension spoofing threat bypass.")
        if common_features.get("has_obfuscation", 0.0) == 1.0:
            alerts.append(
                "Obfuscation indicator triggered: Excessive file entropy suggests compressed or encrypted payload overlay."
            )
            recs.append("🚨 Verify compiler: Scan payload contents for encrypted buffers.")
        if common_features.get("has_macros_or_scripts", 0.0) == 1.0:
            alerts.append(
                "Scripting context triggered: Active VBA macros, document scripts, or shell codes found."
            )
            recs.append("⚠ Disable macro execution inside document readers.")
        if common_features.get("is_encrypted_or_packed", 0.0) == 1.0:
            alerts.append(
                "Encrypted content detected: The file is packed or password-protected, blocking deep scans."
            )
            recs.append("⚠ Request decryption credentials or run scans inside isolated sandbox.")
        if common_features.get("has_network_indicators", 0.0) == 1.0:
            alerts.append(
                "Hyperlink/URI indicators found: Active target connections or network downloads detected."
            )
            recs.append("✓ Audit target URLs to ensure compliance.")

        if not alerts:
            recs.append("✓ Clean Scan: Executable checks match benign baseline distributions.")
            recs.append("✓ Normal usage allowed.")

        return alerts, recs
