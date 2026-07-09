"""Test-only fixture seeding for the e2e (Playwright) critical suite.

This router is registered ONLY when ``ENABLE_TEST_ENDPOINTS=true`` — it never
exists in a production process. The e2e ``global-setup`` calls it to create a
small, deterministic dataset (one repo asset plus a finding per scanner) so the
dashboards and findings views have something to render, then tears it down after
the run using the returned manifest.

The endpoint is public (see PUBLIC_PATHS) because teardown runs without a
session cookie; the ``ENABLE_TEST_ENDPOINTS`` gate is the only access control,
which is acceptable since the router is absent from any real deployment.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, insert, select

from src.db.engine import get_session
from src.db.models import Asset, Finding, RuleViolation

router = APIRouter(prefix="/test", tags=["testing"])

# A stable marker so a seed is idempotent and identifiable for teardown even if a
# manifest is lost — every seeded row carries it.
_SEED_TAG = "e2e-seed"
_ASSET_REF = "github:acme-org/e2e-example-repo"


class SeedBody(BaseModel):
    action: str
    manifest: dict[str, Any] | None = None


def _finding(**kw: Any) -> Finding:
    kw.setdefault("state", "open")
    kw.setdefault("severity", "high")
    return Finding(**kw)


async def _seed() -> dict[str, Any]:
    async with get_session() as session:
        # Idempotent: reuse the asset if a prior seed left it.
        asset_id = (
            await session.execute(select(Asset.id).where(Asset.external_ref == _ASSET_REF))
        ).scalar_one_or_none()
        if asset_id is None:
            asset_id = (
                await session.execute(
                    insert(Asset)
                    .values(
                        type="repo",
                        source="source_connection",
                        source_ref=_SEED_TAG,
                        external_ref=_ASSET_REF,
                        display_name=_ASSET_REF,
                        asset_metadata={"seed": _SEED_TAG},
                    )
                    .returning(Asset.id)
                )
            ).scalar_one()
        asset_id = str(asset_id)

        findings = [
            _finding(
                tool="secret_scanning",
                asset_id=None,
                identity_key=f"{_SEED_TAG}:secret:1",
                severity="critical",
                title="AWS access key committed to source",
                file_path="config/settings.py",
                detail={
                    "seed": _SEED_TAG,
                    "detector": "AWS access key",
                    "Redacted": "AKIA...MPLE",
                    "line": 12,
                    "code_window": 'AWS_KEY = "AKIA...MPLE"',
                    "code_window_start_line": 12,
                },
            ),
            _finding(
                tool="dependencies_scanning",
                asset_id=asset_id,
                identity_key=f"{_SEED_TAG}:dep:1",
                severity="high",
                cve_id="CVE-2024-0001",
                package_name="left-pad",
                package_version="1.0.0",
                detail={"seed": _SEED_TAG, "message": "Vulnerable dependency"},
            ),
            _finding(
                tool="code_scanning",
                asset_id=asset_id,
                identity_key=f"{_SEED_TAG}:sast:1",
                severity="medium",
                file_path="app/handlers.py",
                rule_name="python.sqli",
                engine="semgrep",
                detail={"seed": _SEED_TAG, "message": "Possible SQL injection", "startLine": 42},
            ),
            _finding(
                tool="container_scanning",
                asset_id=asset_id,
                identity_key=f"{_SEED_TAG}:container:1",
                severity="high",
                cve_id="CVE-2024-0002",
                package_name="openssl",
                package_version="1.1.1",
                detail={"seed": _SEED_TAG, "message": "Vulnerable OS package"},
            ),
        ]
        for f in findings:
            session.add(f)
        await session.flush()
        finding_ids = [f.id for f in findings]

    return {"seeded": True, "asset_ids": [asset_id], "finding_ids": finding_ids}


async def _teardown(manifest: dict[str, Any]) -> dict[str, Any]:
    async with get_session() as session:
        # Resolve the seeded asset(s) — from the manifest, or by ref so a lost
        # manifest still cleans up.
        asset_ids = manifest.get("asset_ids") or [
            str(r)
            for r in (
                await session.execute(select(Asset.id).where(Asset.external_ref == _ASSET_REF))
            ).scalars().all()
        ]
        finding_ids = manifest.get("finding_ids") or []

        # Rule evaluation on the seeded findings may have created violations that
        # FK-reference the asset or the findings; clear those before the rows they
        # point at.
        if asset_ids:
            await session.execute(delete(RuleViolation).where(RuleViolation.asset_id.in_(asset_ids)))
        if finding_ids:
            await session.execute(
                delete(RuleViolation).where(
                    RuleViolation.subject_id.in_([str(i) for i in finding_ids])
                )
            )

        if finding_ids:
            await session.execute(delete(Finding).where(Finding.id.in_(finding_ids)))
        else:
            await session.execute(delete(Finding).where(Finding.detail["seed"].astext == _SEED_TAG))

        if asset_ids:
            await session.execute(delete(Asset).where(Asset.id.in_(asset_ids)))
        else:
            await session.execute(delete(Asset).where(Asset.external_ref == _ASSET_REF))
    return {"torn_down": True}


@router.post("/seed")
async def seed(body: SeedBody) -> dict[str, Any]:
    if body.action == "seed":
        return await _seed()
    if body.action == "teardown":
        return await _teardown(body.manifest or {})
    raise HTTPException(status_code=422, detail="action must be 'seed' or 'teardown'")
