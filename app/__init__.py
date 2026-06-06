"""Flask application factory.

Usage:
    from app import create_app
    app = create_app("production")
"""
import os

from flask import Flask, render_template

from .config import config_by_name
from .extensions import db, login_manager, migrate


def create_app(config_name=None):
    config_name = config_name or os.environ.get("FLASK_CONFIG", "default")
    app = Flask(__name__)
    app.config.from_object(config_by_name[config_name])

    # Ensure working directories exist.
    for key in ("UPLOAD_TMP_DIR", "LOCAL_STORAGE_DIR"):
        path = app.config.get(key)
        if path:
            os.makedirs(path, exist_ok=True)

    # Init extensions.
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)

    # Register blueprints.
    from .auth.routes import auth_bp
    from .main.routes import main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    # Models must be imported so create_all / migrations see them.
    from . import models  # noqa: F401

    register_error_handlers(app)
    register_cli(app)

    @app.context_processor
    def inject_globals():
        return {
            "app_name": "CloudGuard File Scanner",
            "engines": {
                "virustotal": app.config.get("ENABLE_VIRUSTOTAL"),
                "clamav": app.config.get("ENABLE_CLAMAV"),
                "storage": "S3" if app.config.get("S3_BUCKET") else "Local disk",
            },
        }

    return app


def register_error_handlers(app):
    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", code=404,
                               message="Page not found."), 404

    @app.errorhandler(413)
    def too_large(_e):
        mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
        return render_template(
            "error.html", code=413,
            message=f"File too large. Maximum upload size is {mb} MB.",
        ), 413

    @app.errorhandler(500)
    def server_error(_e):
        return render_template("error.html", code=500,
                               message="Internal server error."), 500


def register_cli(app):
    @app.cli.command("init-db")
    def init_db():
        """Create all database tables (for quick setup without migrations)."""
        db.create_all()
        print("Database tables created.")
