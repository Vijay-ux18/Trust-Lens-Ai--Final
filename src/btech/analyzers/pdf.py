"""
PDF File Static Analyzer.
"""

import re
from typing import Any, Dict

from btech.analyzers.base import BaseAnalyzer, calculate_entropy


class PDFAnalyzer(BaseAnalyzer):
    """
    Statically analyzes PDF documents for security indicators (JS, embedded stubs, link densities).
    """

    def can_handle(self, extension: str, file_bytes: bytes) -> bool:
        # Check if PDF extension or matches standard PDF magic header '%PDF'
        return extension == "pdf" or (len(file_bytes) >= 4 and file_bytes[:4] == b"%PDF")

    def extract_features(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        entropy = calculate_entropy(file_bytes)

        # Statically scan raw bytes for PDF keywords
        js_count = len(re.findall(b"/JS|/JavaScript", file_bytes, re.IGNORECASE))
        uri_count = len(re.findall(b"/URI|/GoTo", file_bytes, re.IGNORECASE))
        embed_count = len(
            re.findall(b"/EmbeddedFiles|/EmbeddedFile|/Filespec", file_bytes, re.IGNORECASE)
        )
        is_encrypted = 1 if b"/Encrypt" in file_bytes else 0

        # Approximate page count from catalog references
        page_matches = re.findall(b"/Count\\s+(\\d+)", file_bytes)
        page_count = 1
        if page_matches:
            try:
                page_count = max(int(m) for m in page_matches)
            except ValueError:
                pass

        # Estimate metadata count
        meta_keys = [b"/Title", b"/Author", b"/Creator", b"/Producer", b"/CreationDate"]
        metadata_count = sum(1 for key in meta_keys if key in file_bytes)

        return {
            "file_size_kb": len(file_bytes) / 1024,
            "entropy": entropy,
            "page_count": page_count,
            "js_count": js_count,
            "uri_count": uri_count,
            "embed_count": embed_count,
            "is_encrypted": is_encrypted,
            "metadata_count": metadata_count,
            "file_format": "PDF Document",
        }
