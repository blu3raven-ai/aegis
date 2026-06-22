"""Unit tests for the OSV fetcher.

The fetcher's job: pull per-ecosystem ZIPs from OSV's GCS bucket and
yield one parsed-advisory dict per file in the ZIP. Pure I/O + parse,
no DB or MinIO involvement.
"""
from __future__ import annotations

import io
import json
import zipfile
from unittest.mock import patch

import pytest

from src.osv.fetcher import fetch_ecosystem, OSV_BUCKET_BASE_URL


def _make_zip(advisories: list[dict]) -> bytes:
    """Build an in-memory ZIP with one JSON file per advisory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for adv in advisories:
            z.writestr(f"{adv['id']}.json", json.dumps(adv))
    return buf.getvalue()


def test_fetch_ecosystem_yields_each_advisory():
    sample = [
        {"id": "GHSA-aaaa-bbbb-cccc", "summary": "test"},
        {"id": "GHSA-dddd-eeee-ffff", "summary": "another"},
    ]
    zip_bytes = _make_zip(sample)

    with patch("src.osv.fetcher._download_zip", return_value=zip_bytes):
        out = list(fetch_ecosystem("npm"))

    assert len(out) == 2
    assert {a["id"] for a in out} == {"GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"}


def test_fetch_ecosystem_skips_non_json_entries():
    """ZIPs can contain a `all.json` index or other non-advisory files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("README.txt", "not json")
        z.writestr("GHSA-aaaa-bbbb-cccc.json", json.dumps({"id": "GHSA-aaaa-bbbb-cccc"}))

    with patch("src.osv.fetcher._download_zip", return_value=buf.getvalue()):
        out = list(fetch_ecosystem("npm"))

    assert len(out) == 1
    assert out[0]["id"] == "GHSA-aaaa-bbbb-cccc"


def test_fetch_ecosystem_skips_malformed_json():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("good.json", json.dumps({"id": "GHSA-good"}))
        z.writestr("bad.json", "{ not valid json")

    with patch("src.osv.fetcher._download_zip", return_value=buf.getvalue()):
        out = list(fetch_ecosystem("npm"))

    assert len(out) == 1
    assert out[0]["id"] == "GHSA-good"


def test_fetch_ecosystem_url():
    """The URL must match OSV's canonical per-ecosystem path."""
    with patch("src.osv.fetcher._download_zip") as mock_dl:
        mock_dl.return_value = b"PK\x03\x04"  # minimal zip-ish bytes
        with pytest.raises(zipfile.BadZipFile):
            list(fetch_ecosystem("pypi"))
        mock_dl.assert_called_once_with(f"{OSV_BUCKET_BASE_URL}/pypi/all.zip")
