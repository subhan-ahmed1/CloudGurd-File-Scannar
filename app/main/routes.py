"""Main application routes: dashboard, upload/scan, reports, history."""
import json
import os
import tempfile

from flask import (
    Blueprint, render_template, redirect, url_for, flash, request,
    current_app, abort, jsonify,
)
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from sqlalchemy import func

from ..extensions import db
from ..models import ScannedFile, ScanResult
from ..scanner import scan_file as run_scan
from ..storage import s3 as storage

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    return render_template("index.html")


@main_bp.route("/dashboard")
@login_required
def dashboard():
    files = (
        current_user.files.order_by(ScannedFile.uploaded_at.desc())
        .limit(10)
        .all()
    )
    # Aggregate verdict counts for the dashboard charts.
    counts = (
        db.session.query(ScanResult.verdict, func.count(ScanResult.id))
        .join(ScannedFile, ScanResult.file_id == ScannedFile.id)
        .filter(ScannedFile.user_id == current_user.id)
        .group_by(ScanResult.verdict)
        .all()
    )
    stats = {"safe": 0, "suspicious": 0, "malicious": 0, "error": 0}
    for verdict, n in counts:
        stats[verdict] = n
    stats["total"] = sum(stats.values())
    return render_template("dashboard.html", files=files, stats=stats)


@main_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded or uploaded.filename == "":
            flash("Please choose a file to upload.", "warning")
            return redirect(url_for("main.upload"))

        original = secure_filename(uploaded.filename) or "unnamed"
        tmp_dir = current_app.config["UPLOAD_TMP_DIR"]
        os.makedirs(tmp_dir, exist_ok=True)

        fd, tmp_path = tempfile.mkstemp(dir=tmp_dir)
        os.close(fd)
        uploaded.save(tmp_path)

        try:
            size = os.path.getsize(tmp_path)

            # 1. Run the scanner pipeline (hashes + static + AV engines).
            report = run_scan(tmp_path, original)

            # 2. Persist the file to cloud storage (S3 or local fallback).
            stored = storage.store(tmp_path, original)

            # 3. Record everything in the database.
            sf = ScannedFile(
                user_id=current_user.id,
                original_filename=original,
                stored_key=stored["key"],
                storage_backend=stored["backend"],
                size_bytes=size,
                content_type=report["static"]["detected_type"],
                md5=report["hashes"]["md5"],
                sha256=report["hashes"]["sha256"],
            )
            db.session.add(sf)
            db.session.flush()  # assign sf.id

            vt = report["virustotal"]
            clam = report["clamav"]
            sr = ScanResult(
                file_id=sf.id,
                verdict=report["verdict"],
                score=report["score"],
                extension_ok=report["static"]["extension_ok"],
                type_match=report["static"]["type_match"],
                detected_type=report["static"]["detected_type"],
                suspicious_reasons=json.dumps(report["suspicious_reasons"]),
                clamav_engaged=clam.get("engaged", False),
                clamav_infected=clam.get("infected", False),
                clamav_signature=clam.get("signature"),
                vt_engaged=vt.get("engaged", False),
                vt_malicious=vt.get("malicious", 0),
                vt_suspicious=vt.get("suspicious", 0),
                vt_harmless=vt.get("harmless", 0),
                vt_undetected=vt.get("undetected", 0),
                vt_permalink=vt.get("permalink"),
                raw_report=report["raw_json"],
            )
            db.session.add(sr)
            db.session.commit()
            flash("File scanned successfully.", "success")
            return redirect(url_for("main.report", file_id=sf.id))
        except Exception as exc:  # noqa: BLE001
            db.session.rollback()
            current_app.logger.exception("Scan failed")
            flash(f"Scan failed: {exc}", "danger")
            return redirect(url_for("main.upload"))
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    return render_template("upload.html")


@main_bp.route("/report/<int:file_id>")
@login_required
def report(file_id):
    sf = db.session.get(ScannedFile, file_id)
    if sf is None or sf.user_id != current_user.id:
        abort(404)
    reasons = json.loads(sf.result.suspicious_reasons or "[]")
    raw = json.loads(sf.result.raw_report or "{}")
    download_url = None
    if sf.storage_backend == "s3":
        try:
            download_url = storage.presigned_url(sf.storage_backend, sf.stored_key)
        except Exception:
            download_url = None
    return render_template(
        "report.html", file=sf, result=sf.result, reasons=reasons,
        raw=raw, download_url=download_url,
    )


@main_bp.route("/history")
@login_required
def history():
    page = request.args.get("page", 1, type=int)
    verdict = request.args.get("verdict")
    query = current_user.files.order_by(ScannedFile.uploaded_at.desc())
    if verdict in {"safe", "suspicious", "malicious"}:
        query = query.join(ScanResult).filter(ScanResult.verdict == verdict)
    pagination = query.paginate(page=page, per_page=15, error_out=False)
    return render_template(
        "history.html", pagination=pagination, files=pagination.items,
        active_verdict=verdict,
    )


@main_bp.route("/file/<int:file_id>/delete", methods=["POST"])
@login_required
def delete_file(file_id):
    sf = db.session.get(ScannedFile, file_id)
    if sf is None or sf.user_id != current_user.id:
        abort(404)
    try:
        storage.delete(sf.storage_backend, sf.stored_key)
    except Exception:
        current_app.logger.warning("Could not delete stored object")
    db.session.delete(sf)
    db.session.commit()
    flash("File and scan record deleted.", "info")
    return redirect(url_for("main.history"))


@main_bp.route("/report/<int:file_id>/json")
@login_required
def report_json(file_id):
    """Machine-readable report (handy for API-style access / grading)."""
    sf = db.session.get(ScannedFile, file_id)
    if sf is None or sf.user_id != current_user.id:
        abort(404)
    return jsonify(json.loads(sf.result.raw_report or "{}"))


@main_bp.route("/healthz")
def healthz():
    """Liveness probe for load balancers / ECS / k8s."""
    return {"status": "ok"}, 200
