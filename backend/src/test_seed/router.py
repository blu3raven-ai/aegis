"""Test data seed endpoint — only available in non-production environments.

Guarded by TEST_SEED_ENABLED env var and FASTAPI_ENV != "production".
Returns 404 if either condition is not met.
"""
from __future__ import annotations

import os
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from src.storage import (
    read_latest_findings as read_secret_findings,
    write_latest_findings as write_secret_findings,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/test", tags=["test-seed"])


def _is_enabled() -> bool:
    if os.getenv("FASTAPI_ENV", "").lower() == "production":
        return False
    return os.getenv("TEST_SEED_ENABLED", "").lower() in ("1", "true", "yes")


class SeedRequest(BaseModel):
    action: str  # "seed" or "teardown"
    manifest: dict[str, Any] | None = None


SEED_FINDINGS = [
    {
        "secretIdentity": f"si-e2e-{i:03d}",
        "fingerprint": f"fp-e2e-{i:03d}",
        "reviewStatus": ["new", "confirmed", "false_positive", "action_taken"][i % 4],
        "detector": ["generic-api-key", "aws-access-key", "github-pat"][i % 3],
        "repository": ["web-app", "api-server", "auth-service"][i % 3],
        "organization": "acme-corp",
        "source": "github",
        "filePath": f"src/file-{i}.py",
        "secretSnippet": "AKIAIOSFODNN7EXAMPLE",
        "detectedAt": f"2026-04-{(i % 28) + 1:02d}T00:00:00Z",
        "first_seen_at": f"2026-04-{(i % 28) + 1:02d}T00:00:00Z",
        "state": "open",
        "line": 10 + i,
        "commit": f"abc{i:04d}",
        "classificationHistory": [
            {"value": "likely_real", "source": "scanner", "scanDepth": "light",
             "confidence": 0.8, "runId": "run-e2e", "scannedAt": "2026-04-01T00:00:00Z"}
        ],
        "riskScore": 5.0 + (i % 5),
        "occurrenceCount": 1 + (i % 3),
    }
    for i in range(20)
]


@router.post("/seed")
def seed_data(request: Request, payload: SeedRequest) -> Any:
    if not _is_enabled():
        raise HTTPException(status_code=404, detail="Not found")

    if payload.action == "seed":
        existing = read_secret_findings("acme-corp") or []
        # Remove any previous e2e seed data
        cleaned = [f for f in existing if not (f.get("fingerprint") or "").startswith("fp-e2e-")]
        cleaned.extend(SEED_FINDINGS)
        write_secret_findings("acme-corp", cleaned)

        logger.info("Seeded %d e2e test findings for acme-corp", len(SEED_FINDINGS))
        return {
            "seeded": True,
            "org": "acme-corp",
            "count": len(SEED_FINDINGS),
            "fingerprints": [f["fingerprint"] for f in SEED_FINDINGS],
        }

    elif payload.action == "teardown":
        existing = read_secret_findings("acme-corp") or []
        cleaned = [f for f in existing if not (f.get("fingerprint") or "").startswith("fp-e2e-")]
        write_secret_findings("acme-corp", cleaned)

        logger.info("Cleaned up e2e test findings for acme-corp")
        return {"cleaned": True}

    raise HTTPException(status_code=400, detail="Unknown action")
