"""Application configuration.

All sensitive / environment-specific values are read from environment
variables so the same code runs locally, in Docker, and on AWS EC2/RDS/S3
without modification. See .env.example for the full list.
"""
import os
from datetime import timedelta


def _bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    # --- Core Flask ---
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # --- Database (SQLAlchemy) ---
    # Example RDS URL:
    #   postgresql+psycopg2://user:pass@mydb.xxxx.us-east-1.rds.amazonaws.com:5432/scanner
    # Falls back to a local SQLite file so the app runs out-of-the-box.
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///scanner.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_recycle": 280}

    # --- Uploads ---
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_UPLOAD_MB", "64")) * 1024 * 1024
    UPLOAD_TMP_DIR = os.environ.get("UPLOAD_TMP_DIR", "/tmp/fss_uploads")

    # --- Cloud storage (AWS S3) ---
    # If S3_BUCKET is unset, files are kept on the local disk instead, so the
    # project is fully demonstrable without an AWS account.
    S3_BUCKET = os.environ.get("S3_BUCKET")
    S3_REGION = os.environ.get("AWS_REGION", "us-east-1")
    S3_PREFIX = os.environ.get("S3_PREFIX", "uploads/")
    LOCAL_STORAGE_DIR = os.environ.get("LOCAL_STORAGE_DIR", "/tmp/fss_storage")

    # --- Scanner engine ---
    ENABLE_VIRUSTOTAL = _bool(os.environ.get("ENABLE_VIRUSTOTAL"), default=True)
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
    # When True the engine will *upload* unknown files to VirusTotal. When
    # False it only performs a privacy-preserving hash lookup.
    VIRUSTOTAL_UPLOAD_UNKNOWN = _bool(
        os.environ.get("VIRUSTOTAL_UPLOAD_UNKNOWN"), default=False
    )
    # Number of AV engines that must flag a file before it is "malicious".
    VT_MALICIOUS_THRESHOLD = int(os.environ.get("VT_MALICIOUS_THRESHOLD", "1"))

    ENABLE_CLAMAV = _bool(os.environ.get("ENABLE_CLAMAV"), default=False)
    CLAMAV_HOST = os.environ.get("CLAMAV_HOST", "127.0.0.1")
    CLAMAV_PORT = int(os.environ.get("CLAMAV_PORT", "3310"))
    # Alternatively connect via unix socket, e.g. /var/run/clamav/clamd.ctl
    CLAMAV_SOCKET = os.environ.get("CLAMAV_SOCKET")


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
