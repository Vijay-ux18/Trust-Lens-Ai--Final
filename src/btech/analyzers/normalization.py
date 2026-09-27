"""
Feature Normalization & Common Feature Vector Mapping Service.
"""

import os
from typing import Any, Dict, List


class FeatureNormalizer:
    """
    Maps format-specific analyzer dictionary outputs into a uniform 10-Dimensional Common Feature Vector.
    """

    @staticmethod
    def map_to_common_vector(features: Dict[str, Any], filename: str) -> Dict[str, Any]:
        # Determine file extension type
        ext = filename.split(".")[-1].lower() if "." in filename else ""
        is_pe_extension = ext in ["exe", "dll", "sys", "ocx", "drv", "scr", "bin"]

        # 1. File Size
        file_size_kb = float(features.get("file_size_kb", 0.0))

        # 2. Entropy
        entropy = float(features.get("entropy", 0.0))

        # 3. Executable Code
        has_executable_code = 0.0
        if is_pe_extension:
            has_executable_code = 1.0
        elif features.get("js_count", 0) > 0 or features.get("has_macros", 0) == 1:
            has_executable_code = 1.0
        elif features.get("executable_contents", 0) > 0:
            has_executable_code = 1.0
        elif features.get("suspicious_commands_count", 0) > 0:
            has_executable_code = 1.0

        # 4. Obfuscation
        has_obfuscation = 0.0
        if features.get("obfuscation_score", 0) > 3:
            has_obfuscation = 1.0
        elif is_pe_extension and features.get("SectionsMaxEntropy", 0.0) > 7.2:
            has_obfuscation = 1.0
        elif ext in ["zip", "rar"] and entropy > 7.4:
            has_obfuscation = 1.0

        # 5. Network Indicators
        has_network_indicators = 0.0
        if features.get("uri_count", 0) > 0 or features.get("link_count", 0) > 0:
            has_network_indicators = 1.0
        elif features.get("suspicious_commands_count", 0) > 0:
            # Script analyzer might flag wget or curl
            has_network_indicators = 1.0

        # 6. Macros or Scripts
        has_macros_or_scripts = 0.0
        if features.get("has_macros", 0) == 1 or features.get("js_count", 0) > 0:
            has_macros_or_scripts = 1.0
        elif ext in ["js", "vbs", "ps1", "bat", "cmd", "sh"]:
            has_macros_or_scripts = 1.0
        elif features.get("script_contents", 0) > 0:
            has_macros_or_scripts = 1.0

        # 7. Encrypted or Packed
        is_encrypted_or_packed = 0.0
        if features.get("is_encrypted", 0) == 1:
            is_encrypted_or_packed = 1.0
        elif is_pe_extension and features.get("SectionsMaxEntropy", 0.0) > 7.2:
            is_encrypted_or_packed = 1.0

        # 8. Masquerading
        has_masquerading = 0.0
        file_format = features.get("file_format", "")
        # If the file extension says it's a document/image but it contains PE signatures
        if "Executable" in file_format or "Library" in file_format:
            if not is_pe_extension:
                has_masquerading = 1.0
        elif is_pe_extension and file_format == "Malformed Executable":
            has_masquerading = 1.0
        elif features.get("extension_mismatch"):
            has_masquerading = 1.0

        # 9. Metadata Density
        meta_count = float(features.get("metadata_count", 0.0))
        metadata_density = min(1.0, meta_count / 10.0)

        # 10. Suspicious Indicators Count
        susp_count = 0.0
        if has_executable_code == 1.0:
            susp_count += 1.0
        if has_obfuscation == 1.0:
            susp_count += 1.0
        if has_network_indicators == 1.0:
            susp_count += 1.0
        if has_macros_or_scripts == 1.0:
            susp_count += 1.0
        if is_encrypted_or_packed == 1.0:
            susp_count += 1.0
        if has_masquerading == 1.0:
            susp_count += 2.0  # double weight for active bypass
            
        if features.get("nested_suspicious_file_count", 0) > 0:
            susp_count += 1.0
        if features.get("archive_analysis_limited") == 1:
            susp_count += 1.0
        if features.get("embed_count", 0) > 0 or features.get("embedded_count", 0) > 0:
            susp_count += 1.0

        return {
            "file_size_kb": file_size_kb,
            "entropy": entropy,
            "has_executable_code": has_executable_code,
            "has_obfuscation": has_obfuscation,
            "has_network_indicators": has_network_indicators,
            "has_macros_or_scripts": has_macros_or_scripts,
            "is_encrypted_or_packed": is_encrypted_or_packed,
            "has_masquerading": has_masquerading,
            "metadata_density": metadata_density,
            "suspicious_indicators_count": susp_count,
        }

    @staticmethod
    def get_feature_list() -> List[str]:
        """Return the ordered list of keys for mapping to model input arrays."""
        return [
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
