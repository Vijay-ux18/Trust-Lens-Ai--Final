"""
TrustLens AI static file analyzers package.
"""

from btech.analyzers.archive import ArchiveAnalyzer
from btech.analyzers.base import BaseAnalyzer
from btech.analyzers.executable import ExecutableAnalyzer
from btech.analyzers.image import ImageAnalyzer
from btech.analyzers.office import DocAnalyzer, ExcelAnalyzer, PowerPointAnalyzer
from btech.analyzers.pdf import PDFAnalyzer
from btech.analyzers.script import ScriptAnalyzer

__all__ = [
    "BaseAnalyzer",
    "PDFAnalyzer",
    "DocAnalyzer",
    "ExcelAnalyzer",
    "PowerPointAnalyzer",
    "ExecutableAnalyzer",
    "ArchiveAnalyzer",
    "ScriptAnalyzer",
    "ImageAnalyzer",
]
