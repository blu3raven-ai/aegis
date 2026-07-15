"""Finding-detail fat blobs are encrypted at rest (they carry the raw scanned
secret value + code window), and legacy plaintext blobs still read back."""
from __future__ import annotations

import json
import os

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from types import SimpleNamespace  # noqa: E402

import src.shared.finding_detail_blob as blob  # noqa: E402

_FAT = {
    "secretSnippet": "sk-super-secret-value-xyz",
    "raw": {"Secret": "sk-super-secret-value-xyz"},
    "code_window": "api_key=sk-super-secret-value-xyz",
}


def _patch_store(monkeypatch):
    store: dict[str, bytes] = {}
    monkeypatch.setattr(blob, "upload_bytes", lambda key, data, content_type=None: store.__setitem__(key, data))
    monkeypatch.setattr(blob, "download_bytes", lambda key, bucket=None: store.get(key))
    return store


def test_put_detail_blob_encrypts_at_rest(monkeypatch):
    store = _patch_store(monkeypatch)
    key = blob.put_detail_blob(7, _FAT)
    stored = store[key].decode()
    # The stored object is a v2 token, and the plaintext secret is NOT in it.
    assert stored.startswith("v2:")
    assert "sk-super-secret-value-xyz" not in stored


def test_hydrate_round_trips_the_encrypted_blob(monkeypatch):
    _patch_store(monkeypatch)
    key = blob.put_detail_blob(7, _FAT)
    row = SimpleNamespace(id=7, detail={"tool": "secret_scanning"}, detail_blob_key=key)
    hydrated = blob.hydrate_detail(row)
    assert hydrated["secretSnippet"] == "sk-super-secret-value-xyz"
    assert hydrated["raw"]["Secret"] == "sk-super-secret-value-xyz"
    assert hydrated["tool"] == "secret_scanning"  # lean field preserved


def test_legacy_plaintext_blob_still_reads(monkeypatch):
    store = _patch_store(monkeypatch)
    # A blob written before encryption: raw plaintext JSON under the key.
    key = blob.build_blob_key(9)
    store[key] = json.dumps(_FAT, sort_keys=True).encode()
    row = SimpleNamespace(id=9, detail={}, detail_blob_key=key)
    hydrated = blob.hydrate_detail(row)
    assert hydrated["secretSnippet"] == "sk-super-secret-value-xyz"


def test_missing_blob_degrades_to_lean_detail(monkeypatch):
    _patch_store(monkeypatch)  # empty store
    row = SimpleNamespace(id=11, detail={"tool": "secret_scanning"}, detail_blob_key="findings/11/detail.json")
    assert blob.hydrate_detail(row) == {"tool": "secret_scanning"}
