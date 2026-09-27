"""
Base class for format-specific static file analyzers.
"""

import math
from collections import Counter
from typing import Any, Dict


def calculate_entropy(file_bytes: bytes) -> float:
    """
    Calculate the Shannon entropy of a byte array (0.0 to 8.0).
    """
    if not file_bytes:
        return 0.0
    counter = Counter(file_bytes)
    length = len(file_bytes)
    entropy = 0.0
    for count in counter.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy


class BaseAnalyzer:
    """
    Interface definition for all TrustLens AI file analyzer plugins.
    """

    def can_handle(self, extension: str, file_bytes: bytes) -> bool:
        """
        Determine if this analyzer can handle the given file.

        Args:
            extension: The file extension (lowercase, e.g., 'pdf', 'exe').
            file_bytes: The raw byte array of the file contents.

        Returns:
            True if the analyzer supports this file format, False otherwise.
        """
        raise NotImplementedError("Analyzers must implement can_handle()")

    def extract_features(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        """
        Extract security-relevant features from the file bytes.

        Args:
            file_bytes: The raw byte array of the file contents.
            filename: The name of the file for extension checking.

        Returns:
            A dictionary containing parsed features.
        """
        raise NotImplementedError("Analyzers must implement extract_features()")
