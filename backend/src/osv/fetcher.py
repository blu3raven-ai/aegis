"""HTTP fetch + ZIP iteration over OSV per-ecosystem advisory dumps.

OSV publishes daily ZIPs at:
  https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip

Each ZIP contains one JSON file per advisory. This module is pure I/O +
parse — it returns parsed advisory dicts and never touches the DB or MinIO.
"""
from __future__ import annotations

import json
import logging
import zipfile
from io import BytesIO
from typing import Iterator

import requests

logger = logging.getLogger(__name__)

OSV_BUCKET_BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"
_DOWNLOAD_TIMEOUT_S = 120


def _download_zip(url: str) -> bytes:
    """Fetch a ZIP from OSV's GCS bucket. Raises on any HTTP error."""
    resp = requests.get(url, timeout=_DOWNLOAD_TIMEOUT_S, stream=True)
    resp.raise_for_status()
    return resp.content


def fetch_ecosystem(ecosystem: str) -> Iterator[dict]:
    """Stream parsed OSV advisories for one ecosystem.

    Skips non-JSON entries (e.g. README) and malformed JSON files — neither
    should kill the whole refresh, since OSV occasionally publishes index
    files alongside advisories.
    """
    url = f"{OSV_BUCKET_BASE_URL}/{ecosystem}/all.zip"
    logger.info("osv_fetcher: downloading %s", url)
    raw = _download_zip(url)

    with zipfile.ZipFile(BytesIO(raw)) as z:
        for entry in z.namelist():
            if not entry.endswith(".json"):
                continue
            try:
                with z.open(entry) as f:
                    yield json.loads(f.read())
            except (json.JSONDecodeError, KeyError) as exc:
                logger.warning("osv_fetcher: skip malformed entry %s: %s", entry, exc)
                continue
