"""ClamAV integration.

Talks to a running ``clamd`` daemon over a TCP or unix socket using the
``clamd`` python client. ClamAV is optional: if the client library or the
daemon is unavailable the scan is reported as "not engaged" rather than
failing the whole pipeline.
"""
from flask import current_app


def _get_client():
    try:
        import clamd
    except Exception:
        return None, "clamd python package not installed"

    socket_path = current_app.config.get("CLAMAV_SOCKET")
    try:
        if socket_path:
            client = clamd.ClamdUnixSocket(path=socket_path)
        else:
            client = clamd.ClamdNetworkSocket(
                host=current_app.config["CLAMAV_HOST"],
                port=current_app.config["CLAMAV_PORT"],
                timeout=30,
            )
        client.ping()
        return client, None
    except Exception as exc:  # connection refused, timeout, etc.
        return None, f"Could not reach clamd: {exc}"


def scan_file(path: str) -> dict:
    """Scan a file with ClamAV.

    Returns a dict with keys: engaged, infected, signature, error.
    """
    result = {
        "engaged": False,
        "infected": False,
        "signature": None,
        "error": None,
    }

    if not current_app.config.get("ENABLE_CLAMAV"):
        result["error"] = "ClamAV disabled by configuration"
        return result

    client, err = _get_client()
    if client is None:
        result["error"] = err
        return result

    try:
        # INSTREAM avoids needing clamd to share the filesystem with the app
        # (important when the app and clamd run in separate containers).
        with open(path, "rb") as fh:
            response = client.instream(fh)
        result["engaged"] = True
        # response looks like {"stream": ("FOUND", "Eicar-Test-Signature")}
        status, signature = response.get("stream", ("OK", None))
        if status == "FOUND":
            result["infected"] = True
            result["signature"] = signature
    except Exception as exc:
        result["error"] = f"ClamAV scan failed: {exc}"

    return result
