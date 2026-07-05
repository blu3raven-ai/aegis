"""POST a file to a backend-minted presigned URL with retry.

A pre-signed POST (not PUT) is used so the object store enforces the upload-size
cap carried in its policy ``fields`` — an oversized file is rejected at upload
time instead of consuming storage. The file part MUST come after the policy
fields in the multipart body, which httpx does by serialising ``data`` before
``files``.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Callable

import httpx

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_RETRY_BACKOFF = [2, 5, 10]
_REQUEST_TIMEOUT = 120.0

URL_EXPIRED_MARKER = "url_expired"


def post_to_url(
    file_path: Path,
    url: str,
    fields: dict[str, str],
    *,
    _sleep: Callable[[float], None] = time.sleep,
) -> str:
    """Upload a file via a pre-signed multipart POST.

    ``fields`` are the policy/signature fields returned by the backend presign
    endpoint; they are sent as the leading form parts, with the file last.

    Returns:
        "ok"               — upload succeeded
        URL_EXPIRED_MARKER — URL is no longer valid; caller should re-presign
        "fail"             — non-retryable (e.g. oversized) or retries exhausted
    """
    with open(file_path, "rb") as fh:
        data = fh.read()

    for attempt in range(_MAX_RETRIES):
        try:
            with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
                resp = client.post(url, data=fields, files={"file": (file_path.name, data)})
        except httpx.RequestError as exc:
            if attempt < _MAX_RETRIES - 1:
                logger.warning("[!] POST attempt %d network error: %s", attempt + 1, exc)
                _sleep(_RETRY_BACKOFF[attempt])
                continue
            logger.error("[!] POST failed after %d network errors: %s", _MAX_RETRIES, exc)
            return "fail"

        if 200 <= resp.status_code < 300:
            return "ok"

        if resp.status_code == 403 and (
            "SignatureDoesNotMatch" in resp.text or "Request has expired" in resp.text
        ):
            logger.info("[~] Presigned URL expired (403) — caller should re-presign")
            return URL_EXPIRED_MARKER

        if 500 <= resp.status_code < 600 and attempt < _MAX_RETRIES - 1:
            logger.warning("[!] POST attempt %d returned %d", attempt + 1, resp.status_code)
            _sleep(_RETRY_BACKOFF[attempt])
            continue

        logger.error("[!] POST failed with status %d: %s", resp.status_code, resp.text[:200])
        return "fail"

    return "fail"
