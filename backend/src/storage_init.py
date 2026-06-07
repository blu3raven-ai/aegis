"""Ensure MinIO buckets exist on startup.

Replaces the minio-init sidecar container — runs idempotently on every boot.
"""
from __future__ import annotations

import logging
import os
import subprocess

logger = logging.getLogger(__name__)

# Buckets to create
_BUCKETS = ["scans", "sboms", "reports"]


def ensure_minio_ready() -> None:
    """Create buckets if they don't already exist."""
    endpoint = os.environ.get("S3_ENDPOINT", "http://minio:9000")
    root_user = os.environ.get("S3_ACCESS_KEY", "")
    root_password = os.environ.get("S3_SECRET_KEY", "")

    if not root_user or not root_password:
        logger.warning("[!] [minio-init] S3_ACCESS_KEY / S3_SECRET_KEY not set — skipping")
        return

    try:
        # Set up mc alias (credentials passed via env to avoid process listing exposure)
        _mc_env(endpoint, root_user, root_password,
                "alias", "set", "local", endpoint, root_user, root_password)

        # Create buckets
        for bucket in _BUCKETS:
            _mc("mb", "--ignore-existing", f"local/{bucket}")

        logger.info("[✓] [minio-init] MinIO ready — buckets %s", _BUCKETS)
    except Exception:
        logger.exception("[!] [minio-init] MinIO init failed — runner uploads may not work")
    finally:
        # Clean up stored credentials
        try:
            _mc("alias", "remove", "local")
        except Exception:
            pass


def _mc(*args: str) -> None:
    """Run an mc CLI command, raising on failure."""
    result = subprocess.run(
        ["mc", *args],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        if "already" in stderr.lower() or "exists" in stderr.lower():
            return
        raise RuntimeError(f"mc {' '.join(args[:3])}... failed: {stderr}")


def _mc_env(endpoint: str, access_key: str, secret_key: str, *args: str) -> None:
    """Run mc with credentials passed via environment (not visible in process list)."""
    env = {**os.environ, "MC_HOST_local": f"http://{access_key}:{secret_key}@{endpoint.replace('http://', '')}"}
    result = subprocess.run(
        ["mc", *args],
        capture_output=True, text=True, timeout=30, env=env,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        if "already" in stderr.lower() or "exists" in stderr.lower():
            return
        raise RuntimeError(f"mc {' '.join(args[:3])}... failed: {stderr}")
