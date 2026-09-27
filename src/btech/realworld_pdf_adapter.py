"""CIC-compatible TrustLens 10-feature PDF adapter.

The adapter uses only structural/static PDF indicators that can be computed both
from the CIC-Evasive-PDFMal2022 feature table and from raw PDF bytes. It is a
PDF-specific real-world benchmark model; it is not a replacement for the
existing multi-format synthetic model.
"""
from __future__ import annotations
import math, re
from typing import Any, Dict
from btech.analyzers.base import calculate_entropy

FEATURES = [
    "file_size_kb", "structural_complexity", "has_executable_code",
    "has_obfuscation", "has_network_indicators", "has_macros_or_scripts",
    "is_encrypted_or_packed", "has_masquerading", "metadata_density",
    "suspicious_indicators_count",
]

def _count(raw: bytes, pattern: bytes) -> int:
    return len(re.findall(pattern, raw, re.IGNORECASE))

def extract_pdf_features(file_bytes: bytes, filename: str = "sample.pdf") -> Dict[str, float]:
    if not (file_bytes[:4] == b"%PDF" or filename.lower().endswith(".pdf")):
        raise ValueError("PDF adapter requires a PDF file")
    obj=_count(file_bytes,b"/obj\\b"); stream=_count(file_bytes,b"stream\\b")
    endstream=_count(file_bytes,b"endstream\\b"); xref=_count(file_bytes,b"\\bxref\\b")
    trailer=_count(file_bytes,b"\\btrailer\\b"); embedded=_count(file_bytes,b"/EmbeddedFiles|/EmbeddedFile|/Filespec")
    js=_count(file_bytes,b"/JS\\b"); javascript=_count(file_bytes,b"/JavaScript\\b")
    aa=_count(file_bytes,b"/AA\\b"); openaction=_count(file_bytes,b"/OpenAction\\b")
    launch=_count(file_bytes,b"/Launch\\b"); enc=int(b"/Encrypt" in file_bytes)
    obf=_count(file_bytes,b"/ObjStm|/JBIG2Decode|/XFA|/RichMedia")
    acro=_count(file_bytes,b"/AcroForm|/Acroform")
    metadata=sum(1 for k in (b"/Title",b"/Author",b"/Creator",b"/Producer",b"/CreationDate") if k in file_bytes)
    executable=float((js+javascript+aa+openaction+launch)>0)
    scripts=float((js+javascript+aa)>0)
    network=float((openaction+launch)>0)
    obfuscation=float(obf>0)
    encrypted=float(enc>0)
    complexity=math.log1p(max(0,obj+stream+endstream+xref+trailer+embedded))
    metadata_density=min(1.0, metadata/10.0)
    suspicious=executable+obfuscation+network+scripts+encrypted+float(embedded>0)+float(acro>0 or _count(file_bytes,b"/XFA")>0)
    return {
        "file_size_kb": len(file_bytes)/1024.0,
        "structural_complexity": complexity,
        "has_executable_code": executable,
        "has_obfuscation": obfuscation,
        "has_network_indicators": network,
        "has_macros_or_scripts": scripts,
        "is_encrypted_or_packed": encrypted,
        "has_masquerading": 0.0,
        "metadata_density": metadata_density,
        "suspicious_indicators_count": suspicious,
    }
