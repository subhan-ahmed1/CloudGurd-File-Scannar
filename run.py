"""Application entry point.

Local dev:   flask --app run run   (or)  python run.py
Production:  gunicorn "run:app"  (see deploy/ for the systemd unit)
"""
import os

from app import create_app
from app.extensions import db

app = create_app(os.environ.get("FLASK_CONFIG", "default"))


@app.shell_context_processor
def _shell_ctx():
    from app.models import User, ScannedFile, ScanResult
    return {"db": db, "User": User, "ScannedFile": ScannedFile,
            "ScanResult": ScanResult}


if __name__ == "__main__":
    # Create tables on first run if they don't exist (dev convenience).
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
