"""
Unit Tests for plugin analyzers and normalizations.
"""

import io
import zipfile

import pytest

from btech.analyzers.archive import ArchiveAnalyzer
from btech.analyzers.image import ImageAnalyzer
from btech.analyzers.normalization import FeatureNormalizer
from btech.analyzers.office import DocAnalyzer, ExcelAnalyzer, PowerPointAnalyzer
from btech.analyzers.pdf import PDFAnalyzer
from btech.analyzers.script import ScriptAnalyzer


def test_pdf_analyzer():
    analyzer = PDFAnalyzer()
    dummy_pdf = (
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /JS (alert(1)) >>\nendobj\n%%EOF"
    )

    assert analyzer.can_handle("pdf", dummy_pdf) is True
    assert analyzer.can_handle("txt", b"not a pdf") is False

    feats = analyzer.extract_features(dummy_pdf, "test.pdf")
    assert feats["js_count"] > 0
    assert feats["file_format"] == "PDF Document"


def test_office_analyzers():
    doc_an = DocAnalyzer()
    excel_an = ExcelAnalyzer()
    ppt_an = PowerPointAnalyzer()

    # Synthesize dummy OOXML docx ZIP file containing VBA macro Project
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as z:
        z.writestr("word/vbaProject.bin", b"VBA macro bytes")
        z.writestr("word/_rels/document.xml.rels", b'TargetMode="External"')
        z.writestr("word/embeddings/oleObject1.bin", b"OLE object")

    docx_bytes = zip_buf.getvalue()

    assert doc_an.can_handle("docx", docx_bytes) is True
    feats = doc_an.extract_features(docx_bytes, "doc.docx")
    assert feats["has_macros"] == 1
    assert feats["link_count"] == 1
    assert feats["embedded_count"] == 1
    assert feats["file_format"] == "Word Document"


def test_archive_analyzer():
    archive_an = ArchiveAnalyzer()

    # Synthesize zip containing sub-archive and executable
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as z:
        z.writestr("nested.zip", b"sub-zip content")
        z.writestr("malicious.exe", b"PE binary content")

    zip_bytes = zip_buf.getvalue()

    assert archive_an.can_handle("zip", zip_bytes) is True
    feats = archive_an.extract_features(zip_bytes, "archive.zip")
    assert feats["nested_archives"] == 1
    assert feats["executable_contents"] == 1
    assert feats["file_format"] == "ZIP Archive"


def test_script_analyzer():
    script_an = ScriptAnalyzer()
    # Trigger obfuscation score by writing fromCharCode keywords > 5 times
    script_bytes = (
        b"eval(String.fromCharCode(97,98,99)); Invoke-Expression 'powershell.exe -nop'; "
        b"fromCharCode fromCharCode fromCharCode fromCharCode fromCharCode fromCharCode"
    )

    assert script_an.can_handle("ps1", script_bytes) is True
    feats = script_an.extract_features(script_bytes, "script.ps1")
    assert feats["suspicious_commands_count"] > 0
    assert feats["obfuscation_score"] > 0
    assert feats["file_format"] == "PS1 Script"


def test_image_analyzer():
    img_an = ImageAnalyzer()
    dummy_jpg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00"

    assert img_an.can_handle("jpg", dummy_jpg) is True
    feats = img_an.extract_features(dummy_jpg, "photo.jpg")
    assert feats["file_format"] == "JPG Image"


def test_feature_normalization():
    # Simulate docx features
    mock_feats = {
        "file_size_kb": 12.5,
        "entropy": 4.5,
        "has_macros": 1,
        "link_count": 2,
        "embedded_count": 0,
        "file_format": "Word Document",
    }

    vector = FeatureNormalizer.map_to_common_vector(mock_feats, "doc.docx")
    assert vector["file_size_kb"] == 12.5
    assert vector["has_executable_code"] == 1.0  # triggered by has_macros
    assert vector["has_macros_or_scripts"] == 1.0
    assert vector["has_masquerading"] == 0.0
    assert vector["suspicious_indicators_count"] > 0.0
