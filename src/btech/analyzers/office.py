"""
Office Document Static Analyzers (Word, Excel, PowerPoint).
"""

import io
import re
import zipfile
from typing import Any, Dict

from btech.analyzers.base import BaseAnalyzer, calculate_entropy


class DocAnalyzer(BaseAnalyzer):
    """
    Analyzes Word documents (.doc, .docx) for macros, links, and embedded objects.
    """

    def can_handle(self, extension: str, file_bytes: bytes) -> bool:
        return extension in ["doc", "docx", "docm"]

    def extract_features(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        has_macros = 0
        link_count = 0
        embedded_count = 0

        # Determine if XML zip format (.docx)
        if zipfile.is_zipfile(io.BytesIO(file_bytes)):
            try:
                with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                    names = z.namelist()
                    # Check for macro project file
                    if any("vbaProject.bin" in name for name in names):
                        has_macros = 1
                    # Count files in embeddings directory
                    embedded_count = sum(1 for name in names if "word/embeddings/" in name)
                    # Count hyperlinks inside rels files
                    for name in names:
                        if name.endswith(".rels"):
                            rels_content = z.read(name)
                            link_count += len(re.findall(b'TargetMode="External"', rels_content))
            except Exception:
                pass
        else:
            # Legacy binary format (.doc)
            # Scan bytes for macro keywords
            if b"vbaProject" in file_bytes or b"VBA" in file_bytes or b"_VBA_PROJECT" in file_bytes:
                has_macros = 1
            # Check for binary URL structures
            link_count = len(re.findall(b"http://|https://", file_bytes, re.IGNORECASE))
            if b"ObjectPool" in file_bytes or b"Ole" in file_bytes:
                embedded_count = 1

        file_format = "Word Document"
        if filename.endswith(".docm"):
            file_format = "Word Macro-Enabled Document"

        return {
            "file_size_kb": len(file_bytes) / 1024,
            "entropy": calculate_entropy(file_bytes),
            "has_macros": has_macros,
            "link_count": link_count,
            "embedded_count": embedded_count,
            "file_format": file_format,
        }


class ExcelAnalyzer(BaseAnalyzer):
    """
    Analyzes Excel spreadsheets (.xls, .xlsx) for hidden sheets, formulas, and macros.
    """

    def can_handle(self, extension: str, file_bytes: bytes) -> bool:
        return extension in ["xls", "xlsx", "xlsm"]

    def extract_features(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        has_macros = 0
        hidden_sheets = 0
        formula_count = 0

        if zipfile.is_zipfile(io.BytesIO(file_bytes)):
            try:
                with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                    names = z.namelist()
                    if any("vbaProject.bin" in name for name in names):
                        has_macros = 1

                    # Check workbook XML for hidden sheets
                    if "xl/workbook.xml" in names:
                        wb_xml = z.read("xl/workbook.xml")
                        hidden_sheets = len(
                            re.findall(b'state="hidden"|state="veryHidden"', wb_xml)
                        )

                    # Scan sheet XMLs for formula tags '<f>'
                    for name in names:
                        if "xl/worksheets/sheet" in name and name.endswith(".xml"):
                            sheet_xml = z.read(name)
                            formula_count += len(re.findall(b"<f\\s|&lt;f\\s|<f>", sheet_xml))
            except Exception:
                pass
        else:
            # Legacy binary format (.xls)
            if b"vbaProject" in file_bytes or b"VBA" in file_bytes:
                has_macros = 1
            # Simple byte counts for legacy formulas
            formula_count = len(re.findall(b"Formula", file_bytes, re.IGNORECASE))
            if b"BOUNDSHEET" in file_bytes:
                # Basic check for hidden sheets in legacy stream
                hidden_sheets = len(re.findall(b"BOUNDSHEET.*\\x01|BOUNDSHEET.*\\x02", file_bytes))

        file_format = "Excel Spreadsheet"
        if filename.endswith(".xlsm"):
            file_format = "Excel Macro-Enabled Spreadsheet"

        return {
            "file_size_kb": len(file_bytes) / 1024,
            "entropy": calculate_entropy(file_bytes),
            "has_macros": has_macros,
            "hidden_sheets": hidden_sheets,
            "formula_count": formula_count,
            "file_format": file_format,
        }


class PowerPointAnalyzer(BaseAnalyzer):
    """
    Analyzes PowerPoint presentations (.ppt, .pptx) for macros, links, and embedded media.
    """

    def can_handle(self, extension: str, file_bytes: bytes) -> bool:
        return extension in ["ppt", "pptx", "pptm"]

    def extract_features(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        has_macros = 0
        link_count = 0
        media_count = 0

        if zipfile.is_zipfile(io.BytesIO(file_bytes)):
            try:
                with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                    names = z.namelist()
                    if any("vbaProject.bin" in name for name in names):
                        has_macros = 1
                    media_count = sum(1 for name in names if "ppt/media/" in name)
                    for name in names:
                        if name.endswith(".rels"):
                            rels_content = z.read(name)
                            link_count += len(re.findall(b'TargetMode="External"', rels_content))
            except Exception:
                pass
        else:
            if b"vbaProject" in file_bytes or b"VBA" in file_bytes:
                has_macros = 1
            link_count = len(re.findall(b"http://|https://", file_bytes, re.IGNORECASE))
            media_count = len(re.findall(b"media/", file_bytes, re.IGNORECASE))

        file_format = "PowerPoint Presentation"
        if filename.endswith(".pptm"):
            file_format = "PowerPoint Macro-Enabled Presentation"

        return {
            "file_size_kb": len(file_bytes) / 1024,
            "entropy": calculate_entropy(file_bytes),
            "has_macros": has_macros,
            "link_count": link_count,
            "media_count": media_count,
            "file_format": file_format,
        }
