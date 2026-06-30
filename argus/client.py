"""Aegis-side thin client for the Argus verification service.

A runner scanner that today runs the verification loop in-process would instead
call ``ArgusClient.verify(...)`` from its ``_maybe_verify`` seam, shipping the
finding dict plus the code slices the verifier needs. Argus runs the
hunter/skeptic/critic loop and returns the verdicts — the runner stays a thin
client with no LLM key or agent loop of its own.
"""
from __future__ import annotations

from typing import Any

import httpx


class ArgusClient:
    """HTTP client for ``POST /v1/verify`` on an Argus service."""

    def __init__(self, base_url: str, token: str, *, timeout: float = 120.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout

    def verify(
        self,
        scan_id: str,
        scanner: str,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """POST a batch of findings and return the list of result dicts.

        Each ``findings`` entry is a ``VerifyFinding``-shaped dict:
        ``{"finding_id", "detail", "code_context": {"files": [...]}}``.
        """
        payload = {"scan_id": scan_id, "scanner": scanner, "findings": findings}
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.post(
                f"{self._base_url}/v1/verify",
                json=payload,
                headers={"Authorization": f"Bearer {self._token}"},
            )
        resp.raise_for_status()
        return resp.json().get("results", [])
