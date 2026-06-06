# Gunicorn configuration for production on EC2.
# Start with: gunicorn -c deploy/gunicorn.conf.py run:app
import multiprocessing

bind = "127.0.0.1:8000"            # Nginx reverse-proxies to this
workers = multiprocessing.cpu_count() * 2 + 1
threads = 2
timeout = 180                       # large-file scans + VirusTotal polling
worker_class = "gthread"
accesslog = "-"                     # log to stdout (captured by systemd/journald)
errorlog = "-"
loglevel = "info"
