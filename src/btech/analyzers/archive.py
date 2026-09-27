"""
Compressed Archive Static Analyzer (ZIP, RAR).
"""

import io
import re
import zipfile
import tempfile
from typing import Any, Dict

from btech.analyzers.base import BaseAnalyzer


class ArchiveAnalyzer(BaseAnalyzer):
    """
    Analyzes archive formats (ZIP, RAR) for nested files, password encryption, and executable stubs.
    """

    MAX_DEPTH = 3
    MAX_FILES = 100
    MAX_TOTAL_SIZE = 100 * 1024 * 1024  # 100MB
    MAX_FILE_SIZE = 50 * 1024 * 1024   # 50MB

    def __init__(self) -> None:
        super().__init__()
        from btech.analyzers.executable import ExecutableAnalyzer
        from btech.analyzers.pdf import PDFAnalyzer
        from btech.analyzers.office import DocAnalyzer, ExcelAnalyzer, PowerPointAnalyzer
        from btech.analyzers.script import ScriptAnalyzer
        from btech.analyzers.image import ImageAnalyzer
        self.analyzers = [
            ExecutableAnalyzer(),
            PDFAnalyzer(),
            DocAnalyzer(),
            ExcelAnalyzer(),
            PowerPointAnalyzer(),
            ScriptAnalyzer(),
            ImageAnalyzer(),
        ]

    def can_handle(self, extension: str, file_bytes: bytes) -> bool:
        is_zip = extension == "zip" or zipfile.is_zipfile(io.BytesIO(file_bytes))
        is_rar = extension == "rar" or (len(file_bytes) >= 4 and file_bytes[:4] == b"Rar!")
        return is_zip or is_rar

    def extract_features(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        import math
        from collections import Counter

        entropy = 0.0
        if file_bytes:
            counter = Counter(file_bytes)
            length = len(file_bytes)
            for count in counter.values():
                p_x = count / length
                entropy -= p_x * math.log2(p_x)

        ext = filename.split(".")[-1].lower() if "." in filename else "zip"

        state = {
            "nested_archives": 0,
            "executable_contents": 0,
            "script_contents": 0,
            "is_encrypted": 0,
            "file_count": 0,
            "total_extracted_size": 0,
            "archive_analysis_limited": 0,
            "nested_suspicious_file_count": 0,
            "suspicious_nested_paths": [],
        }

        if zipfile.is_zipfile(io.BytesIO(file_bytes)):
            with tempfile.TemporaryDirectory() as temp_dir:
                self._analyze_zip_recursive(file_bytes, filename, 0, temp_dir, state, path_prefix="")
        else:
            # RAR parsing fallback or corrupted archive
            state["executable_contents"] = len(
                re.findall(b"\\.exe|\\.dll|\\.sys|\\.so", file_bytes, re.IGNORECASE)
            )
            state["script_contents"] = len(
                re.findall(b"\\.bat|\\.ps1|\\.vbs|\\.js", file_bytes, re.IGNORECASE)
            )
            state["nested_archives"] = len(
                re.findall(b"\\.zip|\\.rar|\\.tar|\\.gz", file_bytes, re.IGNORECASE)
            )
            if b"\x01\x01\x03" in file_bytes or b"Encrypted" in file_bytes:
                state["is_encrypted"] = 1
            state["file_count"] = state["executable_contents"] + state["script_contents"] + state["nested_archives"] + 1

        return {
            "file_size_kb": len(file_bytes) / 1024,
            "entropy": entropy,
            "nested_archives": state["nested_archives"],
            "executable_contents": state["executable_contents"],
            "script_contents": state["script_contents"],
            "is_encrypted": state["is_encrypted"],
            "file_count": state["file_count"],
            "archive_analysis_limited": state["archive_analysis_limited"],
            "nested_suspicious_file_count": state["nested_suspicious_file_count"],
            "suspicious_nested_paths": state["suspicious_nested_paths"],
            "file_format": f"{ext.upper()} Archive",
        }

    def _analyze_zip_recursive(self, file_bytes: bytes, filename: str, depth: int, temp_dir: str, state: Dict[str, Any], path_prefix: str = "") -> None:
        if depth > self.MAX_DEPTH:
            state["archive_analysis_limited"] = 1
            return

        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                infos = z.infolist()
                state["file_count"] += len(infos)
                
                if state["file_count"] > self.MAX_FILES:
                    state["archive_analysis_limited"] = 1
                    return
                
                for info in infos:
                    if info.is_dir():
                        continue
                        
                    if info.flag_bits & 0x1:
                        state["is_encrypted"] = 1
                        continue
                    
                    if info.file_size > self.MAX_FILE_SIZE:
                        state["archive_analysis_limited"] = 1
                        continue
                        
                    if state["total_extracted_size"] + info.file_size > self.MAX_TOTAL_SIZE:
                        state["archive_analysis_limited"] = 1
                        return
                    
                    name_lower = info.filename.lower()
                    current_path = f"{path_prefix} → {info.filename}" if path_prefix else f"{filename} → {info.filename}"
                    
                    try:
                        extracted_bytes = z.read(info.filename)
                        state["total_extracted_size"] += len(extracted_bytes)
                        self._analyze_file(extracted_bytes, name_lower, depth, temp_dir, state, path_prefix=current_path)
                    except Exception:
                        pass
        except Exception:
            pass

    def _analyze_file(self, file_bytes: bytes, filename: str, depth: int, temp_dir: str, state: Dict[str, Any], path_prefix: str = "") -> None:
        sig = file_bytes[:10] if len(file_bytes) >= 10 else file_bytes
        is_zip = sig.startswith(b"PK\x03\x04") or filename.endswith(".zip")
        
        is_ooxml = False
        if is_zip:
            try:
                with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                    if "[Content_Types].xml" in z.namelist():
                        is_ooxml = True
            except Exception:
                pass
                
        if is_zip and not is_ooxml:
            state["nested_archives"] += 1
            self._analyze_zip_recursive(file_bytes, filename, depth + 1, temp_dir, state, path_prefix=path_prefix)
            return

        ext = filename.split(".")[-1].lower() if "." in filename else ""
        selected_analyzer = None
        for analyzer in getattr(self, "analyzers", []):
            if analyzer.can_handle(ext, file_bytes):
                selected_analyzer = analyzer
                break

        is_suspicious = False
        
        if selected_analyzer:
            try:
                from btech.analyzers.normalization import FeatureNormalizer
                from btech.analyzers.executable import ExecutableAnalyzer
                from btech.analyzers.script import ScriptAnalyzer
                
                feats = selected_analyzer.extract_features(file_bytes, filename)
                common = FeatureNormalizer.map_to_common_vector(feats, filename)
                if common.get("suspicious_indicators_count", 0.0) > 0 or common.get("has_executable_code", 0.0) == 1.0:
                    is_suspicious = True
                
                if isinstance(selected_analyzer, ExecutableAnalyzer):
                    state["executable_contents"] += 1
                elif isinstance(selected_analyzer, ScriptAnalyzer):
                    state["script_contents"] += 1
            except Exception:
                pass
        else:
            is_exec_ext = any(filename.endswith(e) for e in [".exe", ".dll", ".sys", ".so", ".bin"])
            is_script_ext = any(filename.endswith(e) for e in [".bat", ".ps1", ".vbs", ".js", ".cmd", ".sh"])
            if is_exec_ext or is_script_ext:
                is_suspicious = True
                if is_exec_ext:
                    state["executable_contents"] += 1
                if is_script_ext:
                    state["script_contents"] += 1
                    
        if is_suspicious:
            state["nested_suspicious_file_count"] += 1
            state["suspicious_nested_paths"].append(path_prefix)
