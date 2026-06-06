FROM python:3.12-slim

# libmagic1 is required by python-magic for content-type sniffing.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_CONFIG=production

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# 3 workers x 2 threads is a sensible default for a small EC2 instance.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "3", \
     "--threads", "2", "--timeout", "180", "run:app"]
