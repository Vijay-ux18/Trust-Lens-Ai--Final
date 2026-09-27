"""
Script Code Static Analyzer (PS1, VBS, JS, BAT, MSI).
"""

import re
from typing import Any, Dict

from btech.analyzers.base import BaseAnalyzer, calculate_entropy


class ScriptAnalyzer(BaseAnalyzer):
    """
    Analyzes scripts for execution payloads, base64 strings, system shell calls, and obfuscation.
    """

    def can_handle(self, extension: str, file_bytes: bytes) -> bool:
        # Matches script and plain text document extensions
        return extension in ["bat", "ps1", "js", "vbs", "cmd", "sh", "py", "msi", "txt", "csv"]

    def extract_features(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        entropy = calculate_entropy(file_bytes)

        # Convert to string context safely
        try:
            content = file_bytes.decode("utf-8", errors="ignore")
        except Exception:
            content = ""

        content_lower = content.lower()

        # 1. Suspicious command keywords check
        cmd_keywords = [
            "eval",
            "shellexecute",
            "wscript.shell",
            "invoke-expression",
            "iex",
            "downloadstring",
            "downloadfile",
            "powershell.exe",
            "cmd.exe",
            "wscript",
            "cscript",
            "activexobject",
            "xmlhttp",
            "adodb.stream",
            "sh.exe",
            "bash",
            "curl",
            "wget",
            "exec",
            "system",
            "popen",
            "subprocess",
        ]
        suspicious_commands_count = sum(content_lower.count(kw) for kw in cmd_keywords)

        # 2. Obfuscation indicators check
        obfuscation_score = 0

        # Check for hexadecimal character escapes like \x41
        hex_escapes = len(re.findall(r"\\x[0-9a-fA-F]{2}", content))
        if hex_escapes > 10:
            obfuscation_score += 3

        # Check for heavy string concatenations or split parameters
        plus_joins = len(re.findall(r"'\s*\+\s*'", content)) + len(
            re.findall(r'"\s*\+\s*"', content)
        )
        if plus_joins > 10:
            obfuscation_score += 2

        # Check for VBS obfuscation keyword chr() or JavaScript String.fromCharCode
        char_converts = content_lower.count("chr(") + content_lower.count("fromcharcode")
        if char_converts > 5:
            obfuscation_score += 2

        # Check for high Shannon entropy (typically indicates raw packed payload overlay)
        if entropy > 6.8:
            obfuscation_score += 3

        obfuscation_score = min(obfuscation_score, 10)

        # 3. Base64/encoded payload detection
        has_encoded_payload = 0
        # Search for long contiguous alphanumeric blocks that could be base64 strings
        b64_blocks = re.findall(r"[A-Za-z0-9+/]{80,}", content)
        if len(b64_blocks) > 0:
            has_encoded_payload = 1

        ext = filename.split(".")[-1].lower() if "." in filename else "js"
        file_format = (
            f"{ext.upper()} Document" if ext in ["txt", "csv"] else f"{ext.upper()} Script"
        )

        return {
            "file_size_kb": len(file_bytes) / 1024,
            "entropy": entropy,
            "suspicious_commands_count": suspicious_commands_count,
            "obfuscation_score": obfuscation_score,
            "has_encoded_payload": has_encoded_payload,
            "file_format": file_format,
        }
