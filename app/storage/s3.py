"""Cloud storage abstraction.

Primary backend is AWS S3 (the spec's cloud-storage requirement). If no
S3_BUCKET is configured the same interface transparently falls back to local
disk so the application is fully runnable without an AWS account.
"""
import os
import uuid

from flask import current_app


def _backend():
    return "s3" if current_app.config.get("S3_BUCKET") else "local"


def _s3_client():
    import boto3
    return boto3.client("s3", region_name=current_app.config["S3_REGION"])


def store(local_path: str, original_filename: str) -> dict:
    """Persist a file to the configured backend.

    Returns dict: {backend, key} where ``key`` is the S3 object key or the
    local absolute path.
    """
    backend = _backend()
    safe_name = os.path.basename(original_filename)
    unique = f"{uuid.uuid4().hex}_{safe_name}"

    if backend == "s3":
        bucket = current_app.config["S3_BUCKET"]
        key = current_app.config["S3_PREFIX"] + unique
        client = _s3_client()
        # ServerSideEncryption demonstrates "centralized security management".
        client.upload_file(
            local_path, bucket, key,
            ExtraArgs={"ServerSideEncryption": "AES256"},
        )
        return {"backend": "s3", "key": key}

    # local fallback
    base = current_app.config["LOCAL_STORAGE_DIR"]
    os.makedirs(base, exist_ok=True)
    dest = os.path.join(base, unique)
    with open(local_path, "rb") as src, open(dest, "wb") as out:
        out.write(src.read())
    return {"backend": "local", "key": dest}


def presigned_url(backend: str, key: str, expires: int = 300):
    """Return a time-limited download URL (S3 only)."""
    if backend != "s3":
        return None
    client = _s3_client()
    return client.generate_presigned_url(
        "get_object",
        Params={"Bucket": current_app.config["S3_BUCKET"], "Key": key},
        ExpiresIn=expires,
    )


def delete(backend: str, key: str) -> None:
    if backend == "s3":
        _s3_client().delete_object(
            Bucket=current_app.config["S3_BUCKET"], Key=key
        )
    else:
        try:
            os.remove(key)
        except OSError:
            pass
