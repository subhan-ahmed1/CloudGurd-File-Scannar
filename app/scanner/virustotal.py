"""VirusTotal API (v3) integration.

Two modes:
  1. Hash lookup (default, privacy-preserving): we send only the SHA-256 of
     the file. If VirusTotal already has a report we get the verdict back
     instantly without ever transmitting the file's contents.
  2. Upload unknown files (opt-in via VIRUSTOTAL_UPLOAD_UNKNOWN): if the hash
     is unknown and the file is <= 32 MB, upload it for analysis.

A free VirusTotal API key works for both. Requests are kept minimal to
respect the free-tier rate limit (4 requests/min).
"""
import time

import requests
from flask import current_app

_API_BASE = "https://www.virustotal.com/api/v3"


def _headers():
    return {"x-apikey": current_app.config["VIRUSTOTAL_API_KEY"]}


def _parse_stats(attributes: dict) -> dict:
    stats = attributes.get("last_analysis_stats", {}) or {}
    return {
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "harmless": int(stats.get("harmless", 0)),
        "undetected": int(stats.get("undetected", 0)),
    }


def lookup_hash(sha256: str) -> dict:
    """Look up an existing report by hash."""
    result = {
        "engaged": False, "found": False, "error": None,
        "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
        "permalink": None,
    }

    if not current_app.config.get("ENABLE_VIRUSTOTAL"):
        result["error"] = "VirusTotal disabled by configuration"
        return result
    if not current_app.config.get("VIRUSTOTAL_API_KEY"):
        result["error"] = "VIRUSTOTAL_API_KEY not set"
        return result

    try:
        resp = requests.get(
            f"{_API_BASE}/files/{sha256}", headers=_headers(), timeout=30
        )
        result["engaged"] = True
        if resp.status_code == 200:
            attributes = resp.json().get("data", {}).get("attributes", {})
            result["found"] = True
            result.update(_parse_stats(attributes))
            result["permalink"] = f"https://www.virustotal.com/gui/file/{sha256}"
        elif resp.status_code == 404:
            result["found"] = False  # unknown to VirusTotal
        else:
            result["error"] = f"VirusTotal returned HTTP {resp.status_code}"
    except requests.RequestException as exc:
        result["error"] = f"VirusTotal request failed: {exc}"

    return result


def upload_file(path: str, sha256: str, max_wait: int = 60) -> dict:
    """Upload an unknown file and poll for its analysis verdict."""
    result = lookup_hash(sha256)  # reuse shape
    if result.get("error"):
        return result

    try:
        with open(path, "rb") as fh:
            resp = requests.post(
                f"{_API_BASE}/files",
                headers=_headers(),
                files={"file": fh},
                timeout=120,
            )
        if resp.status_code not in (200, 201):
            result["error"] = f"Upload failed: HTTP {resp.status_code}"
            return result

        analysis_id = resp.json().get("data", {}).get("id")
        result["engaged"] = True

        # Poll the analysis endpoint until it completes (bounded).
        deadline = time.time() + max_wait
        while time.time() < deadline:
            a = requests.get(
                f"{_API_BASE}/analyses/{analysis_id}",
                headers=_headers(), timeout=30,
            ).json()
            attrs = a.get("data", {}).get("attributes", {})
            if attrs.get("status") == "completed":
                stats = attrs.get("stats", {})
                result["found"] = True
                result["malicious"] = int(stats.get("malicious", 0))
                result["suspicious"] = int(stats.get("suspicious", 0))
                result["harmless"] = int(stats.get("harmless", 0))
                result["undetected"] = int(stats.get("undetected", 0))
                result["permalink"] = (
                    f"https://www.virustotal.com/gui/file/{sha256}"
                )
                return result
            time.sleep(15)  # respect free-tier rate limits

        result["error"] = "Analysis still pending (timed out waiting)"
    except requests.RequestException as exc:
        result["error"] = f"VirusTotal upload failed: {exc}"

    return result


def scan(path: str, sha256: str) -> dict:
    """Main entry point used by the engine."""
    result = lookup_hash(sha256)
    if (
        result.get("engaged")
        and not result.get("found")
        and not result.get("error")
        and current_app.config.get("VIRUSTOTAL_UPLOAD_UNKNOWN")
    ):
        # Unknown hash and uploading is allowed -> submit the file.
        result = upload_file(path, sha256)
    return result
