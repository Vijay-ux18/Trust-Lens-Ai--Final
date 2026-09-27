"""
Image File Static Analyzer (EXIF and Dimensions Metadata Only).
"""

import io
from typing import Any, Dict

from btech.analyzers.base import BaseAnalyzer, calculate_entropy


class ImageAnalyzer(BaseAnalyzer):
    """
    Statically analyzes image files (.jpg, .png, .gif, .bmp) using headers and EXIF metadata only.
    """

    def can_handle(self, extension: str, file_bytes: bytes) -> bool:
        return extension in ["jpg", "jpeg", "png", "gif", "bmp"]

    def extract_features(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        entropy = calculate_entropy(file_bytes)

        width = 0
        height = 0
        color_mode = "Unknown"
        metadata_count = 0
        is_animated = 0

        # Parse image parameters using Pillow (PIL)
        try:
            from PIL import Image as PILImage

            img = PILImage.open(io.BytesIO(file_bytes))
            width, height = img.size
            color_mode = img.mode

            # Count EXIF keys if present
            if hasattr(img, "_getexif") and img._getexif():
                metadata_count = len(img._getexif())
            elif img.info:
                metadata_count = len(img.info)

            # Check if animated (e.g. animated GIF)
            if hasattr(img, "is_animated") and img.is_animated:
                is_animated = 1
        except Exception:
            # Pillow load failed (corrupted binary or missing PIL tags)
            pass

        ext = filename.split(".")[-1].upper() if "." in filename else "IMG"

        return {
            "file_size_kb": len(file_bytes) / 1024,
            "entropy": entropy,
            "width": width,
            "height": height,
            "color_mode": color_mode,
            "metadata_count": metadata_count,
            "is_animated": is_animated,
            "file_format": f"{ext} Image",
        }
