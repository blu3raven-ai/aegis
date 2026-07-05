"""Tests for storage_init — runner MinIO user is no longer provisioned."""
from __future__ import annotations

import inspect

from src import storage_init


def test_storage_init_does_not_reference_runner_user():
    source = inspect.getsource(storage_init)
    assert "RUNNER_S3_SECRET_KEY" not in source
    assert "runner_user" not in source
    # Bucket creation must still happen
    assert "_BUCKETS" in source or "ensure_minio_ready" in source or "bucket" in source.lower()
