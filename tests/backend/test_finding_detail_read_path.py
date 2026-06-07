"""Read-path tests for the finding detail blob hydration strategy.

Asserts the core performance contract:
  - The unified findings list endpoint (list_findings) never calls MinIO
    get_object regardless of how many findings it pages over.
  - Scanner-specific detail functions (_finding_to_dependencies_alert,
    _finding_to_code_scanning_dict, _finding_to_secret_dict) call get_object
    exactly once per row when a blob key is set.

Mocks are placed at download_bytes (the lowest-level MinIO read call used by
hydrate_detail) so the assertion counts are independent of how many times
higher-level helpers call download_json.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, call, patch

import pytest

from src.db.models import Finding
from src.findings.service import FindingsListFilters, _finding_to_dict, list_findings
from src.shared.finding_queryable_fields import extract_queryable_fields


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_lean_finding(
    id: int = 1,
    tool: str = "dependencies",
    detail_blob_key: str | None = None,
    lean_detail: dict | None = None,
) -> Finding:
    """Build a Finding with only lean keys in detail and an optional blob key."""
    f = Finding()
    f.id = id
    f.tool = tool
    f.org = "example-org"
    f.repo = "example-org/api"
    f.identity_key = f"key-{id}"
    f.severity = "high"
    f.state = "open"
    f.detail = lean_detail or {
        "packageName": "lodash",
        "ecosystem": "npm",
        "advisoryId": "GHSA-0001",
        "cveId": "CVE-2021-0001",
        "vulnerableVersionRange": "< 4.17.21",
        "patchedVersion": "4.17.21",
        "manifestPath": "package.json",
        "currentVersion": "4.17.4",
        "source": "git",
        "scanner": "grype",
        "matchedBy": [],
        "cvssScore": 7.2,
        "advisoryUrl": "https://github.com/advisories/GHSA-0001",
    }
    f.detail_blob_key = detail_blob_key
    f.first_seen_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    f.last_seen_at = datetime(2026, 5, 1, tzinfo=timezone.utc)
    f.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    f.updated_at = datetime(2026, 5, 1, tzinfo=timezone.utc)
    qf = extract_queryable_fields(f.detail or {})
    f.cve_id = qf["cve_id"]
    f.file_path = qf["file_path"]
    f.title = qf["title"]
    f.rule_name = qf["rule_name"]
    f.package_name = qf["package_name"]
    return f


def _make_fat_blob_bytes(extra: dict) -> bytes:
    return json.dumps(extra).encode()


# ---------------------------------------------------------------------------
# List endpoint — ZERO MinIO calls regardless of row count
# ---------------------------------------------------------------------------

class _FakeListSession:
    """Async session double for list_findings — returns canned findings."""

    def __init__(self, findings: list[Finding]):
        self._findings = findings

    async def execute(self, stmt):
        compiled = str(stmt)
        result = MagicMock()
        if "count(" in compiled.lower():
            result.scalar.return_value = len(self._findings)
            return result
        scalars = MagicMock()
        scalars.all.return_value = self._findings
        result.scalars.return_value = scalars
        return result


@pytest.mark.asyncio
async def test_list_findings_zero_minio_calls_no_blob():
    """list_findings over rows with no blob key never touches MinIO."""
    findings = [_make_lean_finding(id=i) for i in range(1, 6)]
    session = _FakeListSession(findings)
    filters = FindingsListFilters(org_id="example-org")

    with patch("src.shared.object_store.download_bytes") as mock_dl:
        await list_findings(filters, session)

    mock_dl.assert_not_called()


@pytest.mark.asyncio
async def test_list_findings_zero_minio_calls_with_blob_keys():
    """list_findings over rows that HAVE blob keys still never calls MinIO.

    _finding_to_dict reads only lean/column fields; it does not call
    hydrate_detail, so the list path is safe even when blobs exist.
    """
    findings = [
        _make_lean_finding(id=i, detail_blob_key=f"findings/{i}/detail.json")
        for i in range(1, 6)
    ]
    session = _FakeListSession(findings)
    filters = FindingsListFilters(org_id="example-org")

    with patch("src.shared.object_store.download_bytes") as mock_dl:
        await list_findings(filters, session)

    mock_dl.assert_not_called()


# ---------------------------------------------------------------------------
# Scanner-specific detail functions — hydrate when blob key is set
# ---------------------------------------------------------------------------

def test_finding_to_dependencies_alert_hydrates_fat_keys():
    """_finding_to_dependencies_alert fetches the blob when detail_blob_key is set."""
    from src.storage import _finding_to_dependencies_alert

    fat = {
        "summary": "Prototype pollution in lodash",
        "description": "Detailed advisory markdown.",
        "publishedAt": "2021-03-05T00:00:00Z",
        "advisoryUpdatedAt": "2021-04-01T00:00:00Z",
        "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-0001"}],
        "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "manifestSnippet": "lodash: 4.17.4",
        "manifestMatchLine": 3,
    }
    blob_key = "findings/1/detail.json"
    f = _make_lean_finding(id=1, detail_blob_key=blob_key)

    with patch("src.shared.object_store.download_bytes", return_value=_make_fat_blob_bytes(fat)) as mock_dl:
        result = _finding_to_dependencies_alert(f)

    # get_object was called for the blob
    mock_dl.assert_called_once_with(blob_key)

    # Fat fields present in result
    assert result["security_advisory"]["description"] == "Detailed advisory markdown."
    assert result["security_advisory"]["published_at"] == "2021-03-05T00:00:00Z"
    assert result["manifest_snippet"] == "lodash: 4.17.4"
    assert result["manifest_match_line"] == 3


def test_finding_to_dependencies_alert_no_minio_when_no_blob():
    """_finding_to_dependencies_alert skips MinIO when detail_blob_key is None."""
    from src.storage import _finding_to_dependencies_alert

    f = _make_lean_finding(id=2, detail_blob_key=None)

    with patch("src.shared.object_store.download_bytes") as mock_dl:
        result = _finding_to_dependencies_alert(f)

    mock_dl.assert_not_called()
    # Lean keys still present
    assert result["security_vulnerability"]["vulnerable_version_range"] == "< 4.17.21"


def test_finding_to_code_scanning_dict_hydrates_fat_keys():
    """_finding_to_code_scanning_dict fetches the blob for snippet and fix_suggestion."""
    from src.storage import _finding_to_code_scanning_dict

    lean_detail = {
        "ruleId": "CWE-89",
        "ruleName": "SQL Injection",
        "filePath": "src/app.py",
        "startLine": 42,
        "endLine": 44,
        "message": "User input reaches SQL query",
        "category": "security",
        "cwe": ["CWE-89"],
        "owasp": [],
        "confidence": "HIGH",
        "language": "python",
        "fileClass": "source",
        "ruleIds": ["CWE-89"],
    }
    fat = {
        "snippet": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
        "fixSuggestion": "Use parameterised queries.",
        "repoHtmlUrl": "https://github.com/example-org/api",
        "dataflowTrace": [],
    }
    blob_key = "findings/10/detail.json"
    f = _make_lean_finding(id=10, tool="code_scanning", detail_blob_key=blob_key, lean_detail=lean_detail)

    with patch("src.shared.object_store.download_bytes", return_value=_make_fat_blob_bytes(fat)) as mock_dl:
        result = _finding_to_code_scanning_dict(f)

    mock_dl.assert_called_once_with(blob_key)
    assert result["snippet"] == "cursor.execute(f'SELECT * FROM users WHERE id={uid}')"
    assert result["fix_suggestion"] == "Use parameterised queries."
    assert result["rule_name"] == "SQL Injection"


def test_finding_to_secret_dict_hydrates_fat_keys():
    """_finding_to_secret_dict spreads the full hydrated detail including fat keys."""
    from src.storage import _finding_to_secret_dict

    lean_detail = {
        "organization": "example-org",
        "secretIdentity": "abc123",
        "fingerprint": "fp1",
        "detector": "github_pat",
        "source": "git",
        "repository": "example-org/api",
        "filePath": "config.yml",
        "line": 7,
        "commit": "deadbeef",
        "detectedAt": "2026-01-01T00:00:00Z",
    }
    fat = {
        "locations": [{"repo": "example-org/api", "file": "config.yml", "line": 7}],
        "classificationHistory": [],
        "secretSnippet": "ghp_REDACTED",
        "aiReasoning": "High confidence GitHub PAT.",
        "raw": {},
    }
    blob_key = "findings/20/detail.json"
    f = _make_lean_finding(id=20, tool="secrets", detail_blob_key=blob_key, lean_detail=lean_detail)
    # review_status is read as an attribute
    f.review_status = "new"

    with patch("src.shared.object_store.download_bytes", return_value=_make_fat_blob_bytes(fat)) as mock_dl:
        result = _finding_to_secret_dict(f)

    mock_dl.assert_called_once_with(blob_key)
    assert result["secretSnippet"] == "ghp_REDACTED"
    assert result["locations"] == [{"repo": "example-org/api", "file": "config.yml", "line": 7}]
    assert result["aiReasoning"] == "High confidence GitHub PAT."


def test_finding_to_secret_dict_no_minio_when_no_blob():
    """_finding_to_secret_dict skips MinIO when detail_blob_key is None."""
    from src.storage import _finding_to_secret_dict

    lean_detail = {
        "organization": "example-org",
        "secretIdentity": "abc123",
        "fingerprint": "fp1",
        "detector": "github_pat",
        "source": "git",
        "repository": "example-org/api",
        "filePath": "config.yml",
        "line": 7,
        "commit": "deadbeef",
        "detectedAt": "2026-01-01T00:00:00Z",
    }
    f = _make_lean_finding(id=21, tool="secrets", detail_blob_key=None, lean_detail=lean_detail)
    f.review_status = "new"

    with patch("src.shared.object_store.download_bytes") as mock_dl:
        result = _finding_to_secret_dict(f)

    mock_dl.assert_not_called()
    assert result["detector"] == "github_pat"


# ---------------------------------------------------------------------------
# Hydration cache — same finding object is not fetched twice
# ---------------------------------------------------------------------------

def test_hydrate_cache_prevents_double_fetch():
    """hydrate_detail only calls MinIO once per row even if called multiple times."""
    from src.shared.finding_detail_blob import hydrate_detail

    blob_key = "findings/99/detail.json"
    fat = {"summary": "Once only"}
    f = _make_lean_finding(id=99, detail_blob_key=blob_key)

    with patch("src.shared.object_store.download_bytes", return_value=_make_fat_blob_bytes(fat)) as mock_dl:
        first = hydrate_detail(f)
        second = hydrate_detail(f)

    assert mock_dl.call_count == 1
    assert first is second
    assert first["summary"] == "Once only"
