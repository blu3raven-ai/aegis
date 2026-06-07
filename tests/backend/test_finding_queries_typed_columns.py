"""Integration tests for typed column population on every write.

Verifies that upsert_finding and _apply_detail both call extract_queryable_fields
and persist cve_id, file_path, title, rule_name, and package_name correctly on
INSERT and UPDATE.

Requires testcontainers Postgres + MinIO (both started by conftest.py).
"""
from __future__ import annotations

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from sqlalchemy import delete as sa_delete, select

from src.db.helpers import run_db
from src.db.models import Finding
from src.shared.finding_queries import upsert_finding
from src.shared.lifecycle import _apply_detail


# ---------------------------------------------------------------------------
# Module-wide fixture: suppress compliance auto-mapper
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _no_compliance_mapper():
    """Patch out compliance auto-mapping — the test DB lacks the mappings table."""
    async def _noop(*args, **kwargs):
        pass

    with patch("src.compliance.auto_mapper.apply_finding_mappings", side_effect=_noop):
        yield


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean(tool: str, org: str) -> None:
    async def _del(session):
        await session.execute(
            sa_delete(Finding).where(Finding.tool == tool, Finding.org == org)
        )
    run_db(_del)


def _upsert(tool: str, org: str, identity_key: str, detail: dict, **kwargs) -> Finding:
    async def _q(session):
        return await upsert_finding(
            session,
            tool=tool,
            org=org,
            repo=f"{org}/repo",
            identity_key=identity_key,
            state="open",
            severity="high",
            detail=detail,
            **kwargs,
        )
    return run_db(_q)


def _fetch(tool: str, org: str, identity_key: str) -> Finding | None:
    async def _q(session):
        result = await session.execute(
            select(Finding).where(
                Finding.tool == tool,
                Finding.org == org,
                Finding.identity_key == identity_key,
            )
        )
        return result.scalars().first()
    return run_db(_q)


# ---------------------------------------------------------------------------
# 1. INSERT — code_scanning
# ---------------------------------------------------------------------------

def test_insert_code_scanning_populates_rule_name_and_file_path(s3_endpoint):
    """code_scanning INSERT sets rule_name and file_path; other typed columns are None."""
    tool = "code_scanning"
    org = "typed-col-test-cs-insert"
    key = "cs-insert-1"
    _clean(tool, org)

    detail = {
        "ruleName": "py-sqli",
        "filePath": "app.py",
        "cwe": "CWE-89",
        "snippet": "...",
        "message": "Unsafe query",
    }
    finding = _upsert(tool, org, key, detail)

    assert finding.rule_name == "py-sqli"
    assert finding.file_path == "app.py"
    assert finding.cve_id is None
    assert finding.title is None
    assert finding.package_name is None


# ---------------------------------------------------------------------------
# 2. INSERT — dependencies
# ---------------------------------------------------------------------------

def test_insert_dependencies_populates_cve_package_and_file_path(s3_endpoint):
    """dependencies INSERT sets cve_id, package_name, and file_path (from manifestPath)."""
    tool = "dependencies"
    org = "typed-col-test-deps-insert"
    key = "deps-insert-1"
    _clean(tool, org)

    detail = {
        "cveId": "CVE-2024-1234",
        "packageName": "requests",
        "manifestPath": "requirements.txt",
        "cvssScore": 7.5,
    }
    finding = _upsert(tool, org, key, detail)

    assert finding.cve_id == "CVE-2024-1234"
    assert finding.package_name == "requests"
    assert finding.file_path == "requirements.txt"
    assert finding.rule_name is None


# ---------------------------------------------------------------------------
# 3. INSERT — secrets
# ---------------------------------------------------------------------------

def test_insert_secrets_populates_file_path_only(s3_endpoint):
    """secrets INSERT sets file_path; other typed columns are None."""
    tool = "secrets"
    org = "typed-col-test-secrets-insert"
    key = "secrets-insert-1"
    _clean(tool, org)

    detail = {
        "detector": "aws_key",
        "filePath": "config.py",
        "fingerprint": "abc",
    }
    finding = _upsert(tool, org, key, detail)

    assert finding.file_path == "config.py"
    assert finding.cve_id is None
    assert finding.rule_name is None
    assert finding.package_name is None
    assert finding.title is None


# ---------------------------------------------------------------------------
# 4. INSERT — container_scanning
# ---------------------------------------------------------------------------

def test_insert_container_scanning_populates_cve_and_package(s3_endpoint):
    """container_scanning INSERT sets cve_id and package_name; file_path is None."""
    tool = "container_scanning"
    org = "typed-col-test-cs2-insert"
    key = "cscan-insert-1"
    _clean(tool, org)

    detail = {
        "cveId": "CVE-2024-9999",
        "packageName": "openssl",
        "imageName": "alpine",
    }
    finding = _upsert(tool, org, key, detail)

    assert finding.cve_id == "CVE-2024-9999"
    assert finding.package_name == "openssl"
    assert finding.file_path is None


# ---------------------------------------------------------------------------
# 5. UPDATE — detail loses a key (overwrite-to-None semantics)
# ---------------------------------------------------------------------------

def test_update_clears_typed_column_when_key_missing(s3_endpoint):
    """UPDATE with detail that lacks cveId must set cve_id to None (not preserve old)."""
    tool = "dependencies"
    org = "typed-col-test-update-clear"
    key = "deps-update-clear-1"
    _clean(tool, org)

    # Seed with cveId present
    _upsert(tool, org, key, {"cveId": "CVE-OLD", "packageName": "pkg"})

    # Re-upsert without cveId
    finding = _upsert(tool, org, key, {"packageName": "pkg"})

    assert finding.cve_id is None


# ---------------------------------------------------------------------------
# 6. UPDATE — detail changes a value
# ---------------------------------------------------------------------------

def test_update_overwrites_typed_column_with_new_value(s3_endpoint):
    """UPDATE with a new cveId value must overwrite the old typed column."""
    tool = "dependencies"
    org = "typed-col-test-update-overwrite"
    key = "deps-update-overwrite-1"
    _clean(tool, org)

    _upsert(tool, org, key, {"cveId": "CVE-OLD", "packageName": "pkg"})
    finding = _upsert(tool, org, key, {"cveId": "CVE-NEW", "packageName": "pkg"})

    assert finding.cve_id == "CVE-NEW"


# ---------------------------------------------------------------------------
# 7. Legacy snake_case fallback
# ---------------------------------------------------------------------------

def test_legacy_snake_case_fallback(s3_endpoint):
    """detail with only snake_case cve_id (no cveId) must still populate cve_id column."""
    tool = "dependencies"
    org = "typed-col-test-snake-case"
    key = "snake-case-legacy-1"
    _clean(tool, org)

    finding = _upsert(tool, org, key, {"cve_id": "CVE-LEGACY"})

    assert finding.cve_id == "CVE-LEGACY"


# ---------------------------------------------------------------------------
# 8. Title is populated from pre-split full detail
# ---------------------------------------------------------------------------

def test_title_populated_from_fat_detail_before_split(s3_endpoint):
    """title column is set from full detail even though title is a fat key not in LEAN_KEYS."""
    tool = "code_scanning"
    org = "typed-col-test-title-fat"
    key = "title-fat-1"
    _clean(tool, org)

    # title is a fat key (not in LEAN_KEYS), but the extractor runs before split
    detail = {
        "title": "SQL injection in app.py",
        "ruleName": "py-sqli",
        "filePath": "app.py",
        "snippet": "dangerous_query()",
    }
    finding = _upsert(tool, org, key, detail)

    assert finding.title == "SQL injection in app.py"


# ---------------------------------------------------------------------------
# 9. Lifecycle _apply_detail path — direct call with MagicMock
# ---------------------------------------------------------------------------

def test_apply_detail_sets_typed_columns_directly():
    """_apply_detail sets all 5 typed columns on the prev object before split."""
    prev = MagicMock(spec=Finding)
    prev.id = 999
    prev.detail_blob_key = None

    with (
        patch("src.shared.finding_detail_blob.split_detail", return_value=({"ruleName": "x"}, {})),
        patch("src.shared.finding_detail_blob.put_detail_blob"),
        patch("src.shared.finding_detail_blob.delete_detail_blob"),
        patch("src.shared.lifecycle.flag_modified"),
    ):
        _apply_detail(prev, "code_scanning", {"ruleName": "x", "filePath": "y.py", "title": "z"})

    assert prev.rule_name == "x"
    assert prev.file_path == "y.py"
    assert prev.title == "z"
    assert prev.cve_id is None
    assert prev.package_name is None


# ---------------------------------------------------------------------------
# 10. Lifecycle _apply_detail via integration (real DB) — dismissed branch
# ---------------------------------------------------------------------------

def test_apply_detail_integration_dismissed_branch(s3_endpoint):
    """_apply_detail sets typed columns on a real Finding row (dismissed-prev branch)."""
    from src.shared.finding_queries import upsert_decision
    from src.shared.lifecycle import apply_lifecycle, ScanContext, LifecycleHooks

    class _SimpleHooks(LifecycleHooks):
        tool = "code_scanning"

        def compute_identity_key(self, raw: dict) -> str:
            return raw.get("key", "")

        def initial_state(self, raw: dict) -> str:
            return "open"

        def extract_repo(self, raw: dict) -> str | None:
            return "acme-org/api"

        def extract_severity(self, raw: dict) -> str | None:
            return "high"

        def extract_detail(self, raw: dict) -> dict:
            return raw.get("detail", {})

        def should_mark_fixed(self, identity_key: str, prev_detail: dict, **kwargs) -> bool:
            return True

    tool = "code_scanning"
    org = "typed-col-lifecycle-dismissed"
    key = "dismissed-typed-1"
    _clean(tool, org)

    # Seed a dismissed finding via upsert_finding (no compliance mapping needed)
    def _seed(session):
        return upsert_finding(
            session,
            tool=tool, org=org, repo="acme-org/api",
            identity_key=key, state="dismissed", severity="high",
            detail={"ruleName": "old-rule"},
        )

    async def _seed_and_dismiss(session):
        await upsert_finding(
            session,
            tool=tool, org=org, repo="acme-org/api",
            identity_key=key, state="dismissed", severity="high",
            detail={"ruleName": "old-rule"},
        )
        await upsert_decision(
            session, tool=tool, org=org, identity_key=key,
            status="dismissed", reason="Risk is tolerable", decided_by="tester",
        )

    run_db(_seed_and_dismiss)

    # Re-scan with new detail — triggers dismissed-prev branch in apply_lifecycle
    ctx = ScanContext(tool=tool, org=org, run_id="run-test")
    hooks = _SimpleHooks()
    apply_lifecycle(hooks, ctx, [{"key": key, "detail": {"ruleName": "new-rule", "filePath": "z.py"}}])

    finding = _fetch(tool, org, key)
    assert finding is not None
    assert finding.rule_name == "new-rule"
    assert finding.file_path == "z.py"


# ---------------------------------------------------------------------------
# 11. Compliance pre-seed: _hydrated_detail still set after INSERT
# ---------------------------------------------------------------------------

def test_hydrated_detail_preseed_still_set_after_insert(s3_endpoint):
    """After INSERT, _hydrated_detail must be set on the returned Finding object.

    This guards the compliance auto-mapper short-circuit that allows apply_finding_mappings
    to read the full (fat+lean) detail without a MinIO round-trip.
    """
    tool = "code_scanning"
    org = "typed-col-test-hydrated"
    key = "hydrated-detail-1"
    _clean(tool, org)

    detail = {
        "ruleName": "py-xss",
        "filePath": "views.py",
        "snippet": "render(request.GET['q'])",  # fat key
        "message": "XSS via GET param",
    }

    async def _q(session):
        return await upsert_finding(
            session,
            tool=tool,
            org=org,
            repo=f"{org}/repo",
            identity_key=key,
            state="open",
            severity="medium",
            detail=detail,
        )

    finding = run_db(_q)

    # The pre-seed attribute must be set so apply_finding_mappings can read fat keys
    assert getattr(finding, "_hydrated_detail", None) is not None
    assert finding._hydrated_detail.get("snippet") == "render(request.GET['q'])"
