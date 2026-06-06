"""Scanner engine.

Orchestrates the full pipeline for one uploaded file and produces a single
structured report plus a verdict in {safe, suspicious, malicious, error}.

Verdict logic (highest severity wins):
  * MALICIOUS  -> ClamAV signature match, OR VirusTotal malicious detections
                  >= VT_MALICIOUS_THRESHOLD, OR an executable disguised as a
                  benign file type.
  * SUSPICIOUS -> suspicious/executable extension, content/extension
                  mismatch, container/macro types, or VirusTotal "suspicious"
                  detections.
  * SAFE       -> nothing flagged.

A numeric 0-100 risk score is also produced for the dashboard gauge.
"""
import json

from flask import current_app

from . import hashing, validators, clamav, virustotal


def _risk_score(verdict, finding, clam, vt):
    score = 0
    if not finding["extension_ok"]:
        score += 40
    if not finding["type_match"]:
        score += 35
    score += min(20, 5 * len(finding["reasons"]))
    if vt.get("malicious"):
        score += min(60, 15 * vt["malicious"])
    if vt.get("suspicious"):
        score += min(20, 5 * vt["suspicious"])
    if clam.get("infected"):
        score = 100
    if verdict == "malicious":
        score = max(score, 80)
    return max(0, min(100, score))


def scan_file(path: str, filename: str) -> dict:
    """Run the complete scan pipeline and return a report dict."""
    cfg = current_app.config

    # 1. Integrity hashes
    hashes = hashing.compute_hashes(path)

    # 2. Static inspection (extension + content type)
    finding = validators.inspect(path, filename)

    # 3. ClamAV (optional)
    clam = clamav.scan_file(path)

    # 4. VirusTotal (optional)
    vt = virustotal.scan(path, hashes["sha256"])

    # --- Decide verdict ---
    reasons = list(finding["reasons"])
    verdict = "safe"

    threshold = cfg.get("VT_MALICIOUS_THRESHOLD", 1)
    executable_disguise = (
        not finding["type_match"]
        and finding["detected_type"] in (
            "application/x-dosexec", "application/x-executable"
        )
    )

    if clam.get("infected"):
        verdict = "malicious"
        reasons.append(
            f"ClamAV signature match: {clam.get('signature')}"
        )
    elif vt.get("malicious", 0) >= threshold and vt.get("found"):
        verdict = "malicious"
        reasons.append(
            f"VirusTotal: {vt['malicious']} engine(s) flagged this file as "
            "malicious."
        )
    elif executable_disguise:
        verdict = "malicious"
    elif (
        not finding["extension_ok"]
        or not finding["type_match"]
        or vt.get("suspicious", 0) > 0
        or finding["reasons"]
    ):
        verdict = "suspicious"

    if vt.get("suspicious", 0) > 0 and vt.get("found"):
        reasons.append(
            f"VirusTotal: {vt['suspicious']} engine(s) marked it suspicious."
        )

    score = _risk_score(verdict, finding, clam, vt)

    report = {
        "verdict": verdict,
        "score": score,
        "hashes": hashes,
        "static": finding,
        "suspicious_reasons": reasons,
        "clamav": clam,
        "virustotal": vt,
        "engines_used": {
            "static_analysis": True,
            "clamav": clam.get("engaged", False),
            "virustotal": vt.get("engaged", False),
        },
    }
    report["raw_json"] = json.dumps(report, indent=2, default=str)
    return report
