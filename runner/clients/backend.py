"""HTTP client for the runner-facing backend endpoints."""
from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from runner.observability.metrics import presign_requests_total

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_BACKOFF_SECONDS = [1, 2, 4]


class BackendError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"backend error {status}: {message}")
        self.status = status
        self.message = message


class BackendClient:
    def __init__(self, portal_url: str, auth_token: str, timeout: float = 15.0) -> None:
        self._base = f"{portal_url.rstrip('/')}/api/v1/agent"
        self._headers = {"Authorization": f"Bearer {auth_token}"}
        self._timeout = timeout

    def update_auth_token(self, new_token: str) -> None:
        # The backend rotates the runner's auth token after every /complete and
        # returns the new value in `newAuthToken`. The streamer + uploader both
        # share this client, so updating in place here means they all pick up
        # the new token on their next call without each holding their own copy.
        self._headers = {"Authorization": f"Bearer {new_token}"}

    def presign_uploads(self, job_id: str, files: list[str]) -> dict[str, dict]:
        """Map each file to its pre-signed POST spec ``{"url", "fields"}``."""
        body = self._request("POST", f"/jobs/{job_id}/uploads/presign", json={"files": files})
        return {
            u["file"]: {"url": u["url"], "fields": u.get("fields", {})}
            for u in body.get("urls", [])
        }

    def list_sbom_downloads(self, job_id: str) -> list[dict[str, str]]:
        body = self._request("GET", f"/jobs/{job_id}/sboms")
        return list(body.get("sboms", []))

    def verification_cache_lookup(self, *, tool: str, hashes: list[str]) -> dict[str, dict]:
        """Prior LLM verification results keyed by verification-input hash, so the
        runner can replay a verdict instead of re-spending tokens. Best-effort —
        callers treat any failure as a cache miss."""
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.post(
                f"{self._base}/verification/cache-lookup",
                headers=self._headers,
                json={"tool": tool, "hashes": hashes},
            )
            resp.raise_for_status()
            return resp.json().get("results", {}) or {}

    def _request(self, method: str, path: str, *, json: Any = None) -> dict[str, Any]:
        url = self._base + path
        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                with httpx.Client(timeout=self._timeout) as client:
                    if method == "GET":
                        resp = client.get(url, headers=self._headers)
                    else:
                        resp = client.post(url, headers=self._headers, json=json)
                if resp.status_code >= 500:
                    last_exc = BackendError(resp.status_code, resp.text)
                    if attempt < _MAX_RETRIES:
                        time.sleep(_BACKOFF_SECONDS[attempt])
                        continue
                    op = "download" if path.endswith("/sboms") else "upload"
                    presign_requests_total.labels(op=op, outcome="error").inc()
                    raise last_exc
                if resp.status_code >= 400:
                    op = "download" if path.endswith("/sboms") else "upload"
                    presign_requests_total.labels(op=op, outcome="error").inc()
                    raise BackendError(resp.status_code, resp.text)
                op = "download" if path.endswith("/sboms") else "upload"
                presign_requests_total.labels(op=op, outcome="ok").inc()
                return resp.json()
            except httpx.RequestError as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES:
                    time.sleep(_BACKOFF_SECONDS[attempt])
                    continue
                op = "download" if path.endswith("/sboms") else "upload"
                presign_requests_total.labels(op=op, outcome="error").inc()
                raise BackendError(0, f"network error: {exc}") from exc
        raise BackendError(0, f"unexpected exit: {last_exc!r}")
