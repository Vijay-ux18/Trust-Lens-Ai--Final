"""
Windows Executable Static Analyzer.
"""

from typing import Any, Dict

import pefile

from btech.analyzers.base import BaseAnalyzer
from btech.preprocess import extract_pe_features


class ExecutableAnalyzer(BaseAnalyzer):
    """
    Analyzes Windows executables (.exe, .dll, .sys) using PE header parsing telemetry.
    """

    def can_handle(self, extension: str, file_bytes: bytes) -> bool:
        is_pe_ext = extension in ["exe", "dll", "sys", "ocx", "drv", "scr", "bin"]
        has_mz = len(file_bytes) >= 2 and file_bytes[:2] == b"MZ"
        return is_pe_ext or has_mz

    def extract_features(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        try:
            # Reuses standard PE parsing logic
            features = extract_pe_features(file_bytes)

            # Format label context
            ext = filename.split(".")[-1].lower() if "." in filename else "exe"
            file_format = "Executable Application"
            if ext == "dll":
                file_format = "Dynamic Link Library"
            elif ext == "sys":
                file_format = "System Driver"

            features["file_size_kb"] = len(file_bytes) / 1024
            features["file_format"] = file_format
            return features
        except pefile.PEFormatError as e:
            # If PE parsing fails but header is MZ, output basic fallback parameters
            import math
            from collections import Counter

            entropy = 0.0
            if file_bytes:
                counter = Counter(file_bytes)
                length = len(file_bytes)
                for count in counter.values():
                    p_x = count / length
                    entropy -= p_x * math.log2(p_x)

            return {
                "file_size_kb": len(file_bytes) / 1024,
                "entropy": entropy,
                "SectionsMaxEntropy": entropy,
                "DllCharacteristics": 0,
                "CheckSum": 0,
                "ImportsNb": 0,
                "SizeOfImage": len(file_bytes),
                "SizeOfCode": len(file_bytes),
                "file_format": "Malformed Executable",
                "parsing_error": str(e),
            }
