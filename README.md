# CloudGuard — Cloud-Based File Security Scanner

A cloud-hosted web application that lets authenticated users upload files and
receive an automated security analysis report. It demonstrates core cloud
computing concepts — cloud storage, scalable deployment, remote processing,
and centralized security management — alongside practical cybersecurity
techniques.

For each uploaded file the system:

1. Generates **MD5** and **SHA-256** integrity hashes.
2. **Validates the file type** by sniffing magic bytes and comparing them to
   the declared extension (catches executables disguised as documents/images).
3. **Detects suspicious extensions** (`.exe`, `.scr`, `.js`, `.vbs`, double
   extensions such as `invoice.pdf.exe`, macro-capable Office formats, etc.).
4. Runs **malware detection** via the **VirusTotal API** (hash lookup, with
   optional upload of unknown files) and/or a local **ClamAV** daemon.
5. Produces an overall verdict — **Safe**, **Suspicious**, or **Malicious** —
   plus a 0–100 risk score and a detailed report.
6. Stores the file in **cloud storage (S3)** and records the user, file, scan
   history, and result in a **managed database (RDS)**.

Users browse past reports through a **dashboard** with charts and a searchable,
filterable **scan history**.

---

## Architecture

```
                Browser (HTML/CSS/Bootstrap/JS)
                          │  HTTPS
                          ▼
        ┌─────────────────────────────────────────┐
        │  EC2 instance                            │
        │   Nginx  ──►  Gunicorn  ──►  Flask app   │
        │                              │           │
        └──────────────────────────────┼──────────┘
              │                │        │
              ▼                ▼        ▼
        ┌──────────┐   ┌────────────┐  ┌──────────────────┐
        │  S3      │   │  RDS       │  │  Scanner engine  │
        │ (files)  │   │ (Postgres/ │  │  • hashing       │
        │          │   │  MySQL)    │  │  • type checks   │
        └──────────┘   └────────────┘  │  • ClamAV (TCP)  │
                                        │  • VirusTotal API│
                                        └──────────────────┘
```

| Layer            | Technology                                  |
|------------------|---------------------------------------------|
| Frontend         | HTML, CSS, Bootstrap 5, Chart.js, vanilla JS|
| Backend          | Flask (application factory + blueprints)    |
| Auth             | Flask-Login, hashed passwords (Werkzeug)    |
| Database / ORM   | SQLAlchemy → PostgreSQL **or** MySQL (RDS)  |
| Cloud storage    | AWS S3 (server-side encrypted)              |
| Malware engines  | VirusTotal API v3, ClamAV (`clamd`)         |
| Server           | Gunicorn behind Nginx                       |
| Deployment       | AWS EC2 + S3 + RDS (Docker option included) |

The application degrades gracefully: with **no AWS account** it uses a local
SQLite database and local-disk storage, so you can run and demo it anywhere.
Each external engine (S3, VirusTotal, ClamAV) is independently toggled by
environment variables.

---

## Project layout

```
file-security-scanner/
├── app/
│   ├── __init__.py          # application factory
│   ├── config.py            # env-driven configuration
│   ├── extensions.py        # db, login manager, migrate
│   ├── models.py            # User, ScannedFile, ScanResult
│   ├── auth/                # registration / login / logout
│   ├── main/                # dashboard, upload, report, history
│   ├── scanner/             # the scanning engine
│   │   ├── __init__.py      #   orchestrator + verdict logic
│   │   ├── hashing.py       #   MD5 / SHA-256
│   │   ├── validators.py    #   extension + content-type checks
│   │   ├── clamav.py        #   ClamAV daemon client
│   │   └── virustotal.py    #   VirusTotal API v3
│   ├── storage/s3.py        # S3 with local-disk fallback
│   ├── templates/           # Jinja2 + Bootstrap views
│   └── static/              # css / js
├── deploy/                  # nginx, gunicorn, systemd, IAM policy
├── Dockerfile
├── docker-compose.yml       # local stack: app + Postgres + ClamAV
├── requirements.txt
├── .env.example
└── run.py                   # entry point (dev + gunicorn target)
```

---

## Quick start (local, zero cloud account needed)

```bash
# 1. Install system dependency for file-type sniffing
#    Debian/Ubuntu: sudo apt-get install libmagic1
#    macOS:         brew install libmagic

# 2. Create a virtualenv and install requirements
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 3. Configure
cp .env.example .env
#   For a basic demo you only need to set SECRET_KEY.
#   To enable real malware lookups, add a free VIRUSTOTAL_API_KEY.

# 4. Initialise the database and run
flask --app run init-db
python run.py
#   → open http://localhost:5000, register, and upload a file
```

> **Test it safely:** download the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/).
> It is completely harmless but every antivirus engine (and VirusTotal)
> flags it, so it reliably produces a **Malicious** verdict for demos.

### Local stack with Docker (adds PostgreSQL + ClamAV)

```bash
# Optionally export your VirusTotal key first:
export ENABLE_VIRUSTOTAL=true VIRUSTOTAL_API_KEY=xxxxx
docker compose up --build
# → http://localhost:5000  (ClamAV's first virus-DB download takes ~1–2 min)
```

---

## Getting a VirusTotal API key

1. Create a free account at <https://www.virustotal.com>.
2. Open your profile → **API key**.
3. Put it in `.env` as `VIRUSTOTAL_API_KEY`.

The free tier allows 4 requests/minute. By default the app performs only a
**hash lookup** (it sends the SHA-256, never the file). Set
`VIRUSTOTAL_UPLOAD_UNKNOWN=true` to upload files VirusTotal hasn't seen before.

---

## Deploying to AWS

This walkthrough uses **EC2 + S3 + RDS**, matching the project's required
service set. Equivalent steps apply to Azure (VM + Blob Storage + Azure
Database) or GCP (Compute Engine + Cloud Storage + Cloud SQL).

### 1. S3 bucket (file storage)
1. Create a bucket, e.g. `cloudguard-uploads-<unique>`, in your region.
2. Keep **Block Public Access** ON — the app uses pre-signed URLs for
   downloads, so the bucket never needs to be public.
3. (Optional) enable default encryption (the app also requests SSE-AES256).

### 2. RDS database (managed database)
1. Create a **PostgreSQL** (or MySQL) instance.
2. Create a database named `scanner` and a user/password.
3. In the RDS security group, allow inbound traffic on `5432` (or `3306`)
   **only from the EC2 instance's security group**.
4. Note the endpoint for `DATABASE_URL`.

### 3. EC2 instance (compute)
1. Launch an Ubuntu instance (t3.small or larger recommended for ClamAV).
2. Attach an **IAM role** using `deploy/iam-policy.json` (replace the bucket
   name) so the app reaches S3 without static credentials.
3. Security group: allow `80`/`443` from the internet and `22` from your IP.

### 4. Provision the instance
```bash
ssh ubuntu@<ec2-public-ip>
sudo apt-get update
sudo apt-get install -y python3-venv nginx libmagic1 git
# Optional ClamAV on the same box:
sudo apt-get install -y clamav-daemon && sudo systemctl enable --now clamav-daemon

sudo mkdir -p /opt/scanner && sudo chown ubuntu:ubuntu /opt/scanner
# copy the project to /opt/scanner (git clone or scp), then:
cd /opt/scanner
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### 5. Configure `.env` on the server
```ini
FLASK_CONFIG=production
SECRET_KEY=<long-random-string>
DATABASE_URL=postgresql+psycopg2://scanner:<pass>@<rds-endpoint>:5432/scanner
S3_BUCKET=cloudguard-uploads-<unique>
AWS_REGION=<region>
ENABLE_VIRUSTOTAL=true
VIRUSTOTAL_API_KEY=<key>
ENABLE_CLAMAV=true          # if you installed clamav-daemon above
```

### 6. Create tables, then start the services
```bash
source venv/bin/activate
flask --app run init-db

sudo cp deploy/scanner.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now scanner

sudo cp deploy/nginx.conf /etc/nginx/sites-available/scanner
sudo ln -s /etc/nginx/sites-available/scanner /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl restart nginx
```

Visit `http://<ec2-public-ip>`. Add a domain and run
`sudo certbot --nginx -d yourdomain.com` for HTTPS.

### Scaling notes (the "scalable deployment" requirement)
- The app is stateless (sessions in signed cookies, files in S3, data in RDS),
  so you can run **several EC2 instances behind an Application Load Balancer**
  and scale them with an **Auto Scaling Group**.
- `Gunicorn` worker/thread counts are tuned in `deploy/gunicorn.conf.py`.
- ClamAV can run as a separate service/instance; point `CLAMAV_HOST` at it.
- The `/healthz` endpoint is provided for ALB / ECS / Kubernetes health checks.

---

## Data model

| Table          | Purpose                                                        |
|----------------|----------------------------------------------------------------|
| `users`        | account + hashed password                                      |
| `scanned_files`| one row per upload: filename, storage key, size, MD5, SHA-256  |
| `scan_results` | verdict, risk score, per-engine findings, full JSON report     |

`scanned_files` is the scan-history record; `scan_results` is one-to-one with
it and holds the detailed analysis.

---

## How the verdict is decided

| Verdict       | Triggered when …                                                            |
|---------------|------------------------------------------------------------------------------|
| **Malicious** | ClamAV signature match, OR VirusTotal malicious ≥ `VT_MALICIOUS_THRESHOLD`, OR an executable disguised as a benign type |
| **Suspicious**| suspicious/executable extension, content↔extension mismatch, macro/container type, or VirusTotal "suspicious" hits |
| **Safe**      | nothing flagged                                                              |

---

## Security considerations built in
- Passwords stored only as salted hashes (never plaintext).
- CSRF protection on all forms (Flask-WTF).
- Open-redirect protection on the post-login `?next` parameter.
- Server-side max upload size + `secure_filename` sanitisation.
- S3 objects are server-side encrypted and downloaded via short-lived
  pre-signed URLs; the bucket stays private.
- Uploaded files are scanned in a temp dir and removed after processing.
- Least-privilege IAM policy scoped to a single bucket prefix.

---

## License
Provided as a course/portfolio project template. Adapt freely.
