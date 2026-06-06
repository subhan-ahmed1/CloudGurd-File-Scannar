"""End-to-end smoke test (no external services required)."""
import os
import tempfile

os.environ["FLASK_CONFIG"] = "development"
os.environ["SECRET_KEY"] = "test-secret"
os.environ["ENABLE_VIRUSTOTAL"] = "false"
os.environ["ENABLE_CLAMAV"] = "false"
_db_fd, _db_path = tempfile.mkstemp(suffix=".db")
os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"

from app import create_app
from app.extensions import db
from app.scanner import scan_file

app = create_app("development")
# The raw test client can't supply CSRF tokens; disable for the harness only.
app.config["WTF_CSRF_ENABLED"] = False

# ---- 1. Scanner engine unit checks ----
with app.app_context():
    tmp = tempfile.mkdtemp()

    # (a) clean text file
    clean = os.path.join(tmp, "notes.txt")
    open(clean, "w").write("just some harmless notes\n")
    r1 = scan_file(clean, "notes.txt")

    # (b) windows EXE bytes disguised as a .jpg
    disguised = os.path.join(tmp, "photo.jpg")
    open(disguised, "wb").write(b"\x4d\x5a" + b"\x00" * 200)  # MZ = PE header
    r2 = scan_file(disguised, "photo.jpg")

    # (c) EICAR antivirus test string (harmless, but a known signature)
    eicar = os.path.join(tmp, "test.com")
    open(eicar, "w").write(
        r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    r3 = scan_file(eicar, "test.com")

    print("clean notes.txt    ->", r1["verdict"], "score", r1["score"],
          "| md5", r1["hashes"]["md5"][:8])
    print("disguised photo.jpg->", r2["verdict"], "score", r2["score"],
          "|", r2["static"]["reasons"][:1])
    print("eicar test.com     ->", r3["verdict"], "score", r3["score"])
    assert r1["verdict"] == "safe", r1["verdict"]
    assert r2["verdict"] == "malicious", r2["verdict"]   # exe disguised as jpg
    assert r3["verdict"] == "suspicious", r3["verdict"]  # .com extension flagged
    assert len(r1["hashes"]["sha256"]) == 64

# ---- 2. Full HTTP flow via test client ----
with app.app_context():
    db.create_all()

client = app.test_client()

# register
resp = client.post("/register", data={
    "username": "alice", "email": "alice@example.com",
    "password": "supersecret1", "confirm": "supersecret1",
    "submit": "Create account",
}, follow_redirects=True)
assert resp.status_code == 200, resp.status_code

# login
resp = client.post("/login", data={
    "username": "alice", "password": "supersecret1", "submit": "Sign in",
}, follow_redirects=True)
assert b"Dashboard" in resp.data, "login failed"

# upload + scan
import io
data = {"file": (io.BytesIO(b"\x4d\x5a" + b"\x00" * 100), "invoice.pdf.exe")}
resp = client.post("/upload", data=data, content_type="multipart/form-data",
                   follow_redirects=True)
assert resp.status_code == 200
assert (b"Malicious" in resp.data or b"Suspicious" in resp.data), "no verdict shown"

# history + dashboard render
assert client.get("/history").status_code == 200
assert client.get("/dashboard").status_code == 200
assert client.get("/healthz").json == {"status": "ok"}

print("\nALL SMOKE TESTS PASSED")
