"""SQLAlchemy models.

Three tables cover the spec's data requirements:
  * User         -> account / authentication info
  * ScannedFile  -> one row per uploaded file (the "uploaded files" + scan
                    history record)
  * ScanResult   -> the detailed verdict produced by the scanner engine,
                    one-to-one with a ScannedFile.
"""
from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from .extensions import db, login_manager


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    files = db.relationship(
        "ScannedFile", backref="owner", lazy="dynamic",
        cascade="all, delete-orphan",
    )

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"


class ScannedFile(db.Model):
    __tablename__ = "scanned_files"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )

    original_filename = db.Column(db.String(255), nullable=False)
    stored_key = db.Column(db.String(512), nullable=False)  # S3 key or local path
    storage_backend = db.Column(db.String(16), default="s3")  # s3 | local
    size_bytes = db.Column(db.BigInteger, default=0)
    content_type = db.Column(db.String(128))

    md5 = db.Column(db.String(32), index=True)
    sha256 = db.Column(db.String(64), index=True)

    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    result = db.relationship(
        "ScanResult", backref="file", uselist=False,
        cascade="all, delete-orphan",
    )

    def __repr__(self):
        return f"<ScannedFile {self.original_filename} ({self.sha256[:10]}...)>"


class ScanResult(db.Model):
    __tablename__ = "scan_results"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(
        db.Integer, db.ForeignKey("scanned_files.id"), nullable=False, index=True
    )

    # Overall verdict: safe | suspicious | malicious | error
    verdict = db.Column(db.String(16), nullable=False, default="safe", index=True)
    score = db.Column(db.Integer, default=0)  # 0-100 risk score

    # Individual check outputs
    extension_ok = db.Column(db.Boolean, default=True)
    type_match = db.Column(db.Boolean, default=True)
    detected_type = db.Column(db.String(128))
    suspicious_reasons = db.Column(db.Text)  # JSON list of strings

    clamav_engaged = db.Column(db.Boolean, default=False)
    clamav_infected = db.Column(db.Boolean, default=False)
    clamav_signature = db.Column(db.String(255))

    vt_engaged = db.Column(db.Boolean, default=False)
    vt_malicious = db.Column(db.Integer, default=0)
    vt_suspicious = db.Column(db.Integer, default=0)
    vt_harmless = db.Column(db.Integer, default=0)
    vt_undetected = db.Column(db.Integer, default=0)
    vt_permalink = db.Column(db.String(512))

    raw_report = db.Column(db.Text)  # full JSON report for the detail view
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<ScanResult {self.verdict} score={self.score}>"
