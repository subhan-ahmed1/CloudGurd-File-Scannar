"""Static file inspection: extension policy + content-type consistency.

This module performs the cheap, offline checks the spec calls for:
  * detect suspicious / executable extensions
  * detect double extensions (e.g. invoice.pdf.exe)
  * compare the declared extension against the *actual* file content
    sniffed from its magic bytes.

``python-magic`` is used when available (libmagic). If libmagic is not
installed the module falls back to a small built-in magic-byte table so the
project still runs everywhere.
"""
import os

# Extensions commonly abused to deliver malware.
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe",
    ".js", ".jse", ".jar", ".ps1", ".psm1", ".msi", ".msp", ".hta",
    ".cpl", ".dll", ".sys", ".reg", ".lnk", ".wsf", ".wsh", ".gadget",
}

# Archive/macro-bearing types that warrant extra caution but are not
# automatically malicious.
WATCHLIST_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".iso", ".img", ".docm", ".xlsm", ".pptm",
}

# Minimal magic-byte signatures used when libmagic is unavailable.
_MAGIC_SIGNATURES = [
    (b"\x4d\x5a", "application/x-dosexec"),                 # PE / EXE
    (b"\x7f\x45\x4c\x46", "application/x-executable"),       # ELF
    (b"\x25\x50\x44\x46", "application/pdf"),                # PDF
    (b"\x50\x4b\x03\x04", "application/zip"),                # ZIP/OOXML
    (b"\x89\x50\x4e\x47", "image/png"),                      # PNG
    (b"\xff\xd8\xff", "image/jpeg"),                         # JPEG
    (b"\x47\x49\x46\x38", "image/gif"),                      # GIF
    (b"\x52\x61\x72\x21", "application/x-rar"),              # RAR
    (b"\x1f\x8b", "application/gzip"),                       # GZIP
]

# Map common extensions to the content type families we expect.
_EXT_TO_TYPE = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".zip": "application/zip",
    ".docx": "application/zip",   # OOXML is a zip container
    ".xlsx": "application/zip",
    ".pptx": "application/zip",
    ".exe": "application/x-dosexec",
    ".dll": "application/x-dosexec",
}


def _detect_with_libmagic(path: str):
    try:
        import magic  # python-magic
    except Exception:
        return None
    try:
        return magic.from_file(path, mime=True)
    except Exception:
        return None


def _detect_with_signatures(path: str):
    try:
        with open(path, "rb") as fh:
            header = fh.read(16)
    except OSError:
        return None
    for sig, mime in _MAGIC_SIGNATURES:
        if header.startswith(sig):
            return mime
    return "application/octet-stream"


def detect_content_type(path: str) -> str:
    """Return the best-effort detected MIME type of the file content."""
    return _detect_with_libmagic(path) or _detect_with_signatures(path)


def get_extensions(filename: str):
    """Return (primary_ext, all_exts) lowercased, including dots."""
    name = filename.lower()
    parts = name.split(".")
    if len(parts) <= 1:
        return "", []
    exts = ["." + p for p in parts[1:]]
    return exts[-1], exts


def inspect(path: str, filename: str) -> dict:
    """Run all static checks and return a structured finding dict."""
    primary_ext, all_exts = get_extensions(filename)
    detected = detect_content_type(path)
    reasons = []

    extension_ok = True
    if primary_ext in SUSPICIOUS_EXTENSIONS:
        extension_ok = False
        reasons.append(f"Executable/script extension '{primary_ext}' detected.")

    # Double extension trick, e.g. report.pdf.exe
    if len(all_exts) >= 2 and all_exts[-1] in SUSPICIOUS_EXTENSIONS:
        reasons.append(
            "Double extension detected ("
            + "".join(all_exts)
            + ") — common disguise technique."
        )

    if primary_ext in WATCHLIST_EXTENSIONS:
        reasons.append(
            f"Container/macro-capable type '{primary_ext}' — contents not "
            "inspected recursively."
        )

    # Content vs declared-extension mismatch.
    type_match = True
    expected = _EXT_TO_TYPE.get(primary_ext)
    if expected and detected and detected != "application/octet-stream":
        if expected not in detected and detected not in expected:
            # e.g. a file named photo.jpg whose bytes are a Windows EXE
            type_match = False
            reasons.append(
                f"Content type '{detected}' does not match declared "
                f"extension '{primary_ext}'."
            )
            if detected in ("application/x-dosexec",
                            "application/x-executable"):
                reasons.append(
                    "File is an executable disguised as a non-executable."
                )

    return {
        "primary_extension": primary_ext,
        "all_extensions": all_exts,
        "detected_type": detected,
        "extension_ok": extension_ok,
        "type_match": type_match,
        "reasons": reasons,
    }
