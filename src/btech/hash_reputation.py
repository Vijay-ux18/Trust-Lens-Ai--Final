"""Optional hash-based reputation lookup for TrustLens AI.

The module computes SHA-256 locally and, when a VIRUSTOTAL_API_KEY is supplied,
queries VirusTotal for that hash only. The file bytes are never uploaded.
This is supporting threat intelligence, not ML accuracy.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any

import requests

VT_URL = "https://www.virustotal.com/api/v3/files/{}"


def sha256_hex(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def lookup_virustotal_hash(file_bytes: bytes, timeout: float = 8.0) -> dict[str, Any]:
    """Look up a SHA-256 hash in VirusTotal without uploading the file."""
    digest = sha256_hex(file_bytes)
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    result: dict[str, Any] = {
        "sha256": digest,
        "provider": "VirusTotal",
        "status": "not_configured",
        "known": None,
        "detection_count": None,
        "total_engines": None,
        "note": "No API key configured; no external lookup was performed.",
    }
    if not api_key:
        return result

    try:
        response = requests.get(
            VT_URL.format(digest),
            headers={"x-apikey": api_key, "Accept": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        result.update(status="error", note=f"External reputation lookup failed: {exc}")
        return result

    if response.status_code == 404:
        result.update(status="not_found", known=False, note="Hash was not found in the provider database.")
        return result
    if response.status_code == 429:
        result.update(status="rate_limited", note="Provider rate limit reached; try again later.")
        return result
    if response.status_code == 401:
        result.update(status="unauthorized", note="The configured API key was rejected.")
        return result
    if not response.ok:
        result.update(status="error", note=f"Provider returned HTTP {response.status_code}.")
        return result

    try:
        attrs = response.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        total = int(sum(int(v) for v in stats.values()))
        result.update(
            status="found",
            known=True,
            detection_count=malicious,
            total_engines=total,
            note="Hash reputation only; the uploaded file was not sent to the provider.",
        )
        return result
    except (KeyError, TypeError, ValueError) as exc:
        result.update(status="error", note=f"Unexpected provider response: {exc}")
        return result
