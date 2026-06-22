"""Tests for Dependencies scanner orchestration."""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

from src.shared.enrichment import ingest_findings_jsonl


def test_ingest_findings_jsonl(tmp_path: Path):
    findings = [
        {
            "repository": {"name": "repo1", "full_name": "org1/repo1"},
            "dependency": {"package": {"name": "express", "ecosystem": "npm"}},
            "security_advisory": {"ghsa_id": "CVE-2024-1234", "severity": "critical"},
            "state": "open",
        },
        {
            "repository": {"name": "repo2", "full_name": "org1/repo2"},
            "dependency": {"package": {"name": "flask", "ecosystem": "pip"}},
            "security_advisory": {"ghsa_id": "CVE-2024-5678", "severity": "medium"},
            "state": "open",
        },
    ]
    jsonl_path = tmp_path / "findings.jsonl"
    jsonl_path.write_text("\n".join(json.dumps(f) for f in findings), encoding="utf-8")

    alerts = ingest_findings_jsonl("org1", "run-1", jsonl_path)
    assert len(alerts) == 2
    assert alerts[0]["dependency"]["package"]["name"] == "express"
    assert alerts[0]["security_advisory"]["severity"] == "critical"
    assert alerts[1]["dependency"]["package"]["name"] == "flask"


def test_ingest_findings_jsonl_missing_file(tmp_path: Path):
    alerts = ingest_findings_jsonl("org", "run", tmp_path / "missing.jsonl")
    assert alerts == []


def test_ingest_findings_jsonl_empty_file(tmp_path: Path):
    jsonl_path = tmp_path / "findings.jsonl"
    jsonl_path.write_text("", encoding="utf-8")
    alerts = ingest_findings_jsonl("org", "run", jsonl_path)
    assert alerts == []


def test_ingest_findings_jsonl_skips_malformed_lines(tmp_path: Path):
    content = textwrap.dedent("""\
        {"repository":{"name":"repo"},"dependency":{"package":{"name":"a"}},"security_advisory":{"severity":"low"},"state":"open"}
        not valid json
        {"repository":{"name":"repo"},"dependency":{"package":{"name":"b"}},"security_advisory":{"severity":"high"},"state":"open"}
    """)
    jsonl_path = tmp_path / "findings.jsonl"
    jsonl_path.write_text(content, encoding="utf-8")
    alerts = ingest_findings_jsonl("org", "run", jsonl_path)
    assert len(alerts) == 2


def test_get_scan_sources_for_org_container_images(monkeypatch):
    import src.shared.config as config
    from src.shared.config import get_scan_sources_for_org

    monkeypatch.setattr(config, "_read_source_connections", lambda: [
        {
            "id": "src_1",
            "category": "container-images",
            "sourceType": "ghcr",
            "name": "GHCR",
            "auth": {"orgOrOwner": "test-org", "token": "ghp_test"},
            "scanScope": "all-except-excluded",
            "excludedItems": ["ghcr.io/test-org/old-app:latest"],
            "syncSchedule": "6h",
            "status": "connected",
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z",
            "discoveredItems": [
                "ghcr.io/test-org/app:latest",
                "ghcr.io/test-org/api:v2",
                "ghcr.io/test-org/old-app:latest",
            ],
        },
    ])

    sources = get_scan_sources_for_org("test-org")
    assert len(sources) == 1
    images = sources[0].container_images
    assert "ghcr.io/test-org/app:latest" in images
    assert "ghcr.io/test-org/api:v2" in images
    assert "ghcr.io/test-org/old-app:latest" not in images  # excluded
    assert len(images) == 2


def test_get_scan_sources_for_org_empty(monkeypatch):
    import src.shared.config as config
    from src.shared.config import get_scan_sources_for_org

    monkeypatch.setattr(config, "_read_source_connections", lambda: [])

    assert get_scan_sources_for_org("test-org") == []


def test_get_scan_sources_for_org_repo_urls(monkeypatch):
    import src.shared.config as config
    from src.shared.config import get_scan_sources_for_org

    monkeypatch.setattr(config, "_read_source_connections", lambda: [
        {
            "id": "src_gh",
            "category": "code-repositories",
            "sourceType": "github",
            "name": "GitHub",
            "auth": {"orgOrOwner": "test-org", "token": "ghp_test"},
            "scanScope": "all-except-excluded",
            "excludedItems": ["old-repo"],
            "syncSchedule": "6h",
            "status": "connected",
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z",
            "discoveredItems": ["app", "api", "old-repo"],
        },
        {
            "id": "src_gl",
            "category": "code-repositories",
            "sourceType": "gitlab",
            "name": "GitLab",
            "auth": {"orgOrOwner": "test-org", "instanceUrl": "https://gitlab.example.com", "token": "glpat_test"},
            "scanScope": "all",
            "excludedItems": [],
            "syncSchedule": "6h",
            "status": "connected",
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z",
            "discoveredItems": ["infra"],
        },
    ])

    sources = get_scan_sources_for_org("test-org")
    all_urls = [url for s in sources for url in s.repo_urls]
    assert "https://github.com/test-org/app.git" in all_urls
    assert "https://github.com/test-org/api.git" in all_urls
    assert any("old-repo" in u for u in all_urls) is False
    assert "https://gitlab.example.com/test-org/infra.git" in all_urls
    assert len(all_urls) == 3


def test_get_scan_sources_skips_non_connected_status(monkeypatch):
    import src.shared.config as config
    from src.shared.config import get_scan_sources_for_org

    monkeypatch.setattr(config, "_read_source_connections", lambda: [
        {
            "id": "src_err",
            "category": "code-repositories",
            "sourceType": "github",
            "name": "GitHub Error",
            "auth": {"orgOrOwner": "test-org", "token": "ghp_test"},
            "scanScope": "all",
            "excludedItems": [],
            "syncSchedule": "6h",
            "status": "error",
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z",
            "discoveredItems": ["repo-a"],
        },
        {
            "id": "src_ok",
            "category": "code-repositories",
            "sourceType": "github",
            "name": "GitHub OK",
            "auth": {"orgOrOwner": "test-org", "token": "ghp_test"},
            "scanScope": "all",
            "excludedItems": [],
            "syncSchedule": "6h",
            "status": "connected",
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z",
            "discoveredItems": ["repo-b"],
        },
    ])

    sources = get_scan_sources_for_org("test-org")
    all_urls = [url for s in sources for url in s.repo_urls]
    assert len(all_urls) == 1
    assert any("repo-b" in u for u in all_urls)
    assert not any("repo-a" in u for u in all_urls)


def test_get_scan_sources_scan_scope_all_ignores_exclusions(monkeypatch):
    import src.shared.config as config
    from src.shared.config import get_scan_sources_for_org

    monkeypatch.setattr(config, "_read_source_connections", lambda: [
        {
            "id": "src_1",
            "category": "code-repositories",
            "sourceType": "github",
            "name": "GitHub",
            "auth": {"orgOrOwner": "test-org", "token": "ghp_test"},
            "scanScope": "all",
            "excludedItems": ["old-repo"],
            "syncSchedule": "6h",
            "status": "connected",
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z",
            "discoveredItems": ["app", "old-repo"],
        },
    ])

    sources = get_scan_sources_for_org("test-org")
    all_urls = [url for s in sources for url in s.repo_urls]
    assert len(all_urls) == 2


def test_get_scan_sources_scan_scope_excluded_applies_exclusions(monkeypatch):
    import src.shared.config as config
    from src.shared.config import get_scan_sources_for_org

    monkeypatch.setattr(config, "_read_source_connections", lambda: [
        {
            "id": "src_1",
            "category": "code-repositories",
            "sourceType": "github",
            "name": "GitHub",
            "auth": {"orgOrOwner": "test-org", "token": "ghp_test"},
            "scanScope": "all-except-excluded",
            "excludedItems": ["old-repo"],
            "syncSchedule": "6h",
            "status": "connected",
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z",
            "discoveredItems": ["app", "old-repo"],
        },
    ])

    sources = get_scan_sources_for_org("test-org")
    all_urls = [url for s in sources for url in s.repo_urls]
    assert len(all_urls) == 1
    assert any("app" in u for u in all_urls)
    assert not any("old-repo" in u for u in all_urls)


def test_get_scan_sources_does_not_embed_token(monkeypatch):
    """Tokens should NOT be embedded in URLs — auth is via GIT_TOKEN/GIT_ASKPASS."""
    import src.shared.config as config
    from src.shared.config import get_scan_sources_for_org

    monkeypatch.setattr(config, "_read_source_connections", lambda: [
        {
            "id": "src_gh",
            "category": "code-repositories",
            "sourceType": "github",
            "name": "GitHub",
            "auth": {"orgOrOwner": "test-org", "token": "ghp_abc123"},
            "scanScope": "all",
            "excludedItems": [],
            "syncSchedule": "6h",
            "status": "connected",
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z",
            "discoveredItems": ["app"],
        },
    ])

    sources = get_scan_sources_for_org("test-org")
    all_urls = [url for s in sources for url in s.repo_urls]
    assert "https://github.com/test-org/app.git" in all_urls
    # Token must NOT appear in URL
    assert not any("ghp_abc123" in u for u in all_urls)


def test_get_scan_sources_container_images_skips_non_connected(monkeypatch):
    import src.shared.config as config
    from src.shared.config import get_scan_sources_for_org

    monkeypatch.setattr(config, "_read_source_connections", lambda: [
        {
            "id": "src_1", "category": "container-images", "sourceType": "ghcr",
            "name": "GHCR", "auth": {"orgOrOwner": "test-org", "token": "ghp_test"},
            "scanScope": "all", "excludedItems": [], "syncSchedule": "6h",
            "status": "not-synced",
            "createdAt": "2026-01-01T00:00:00Z", "updatedAt": "2026-01-01T00:00:00Z",
            "discoveredItems": ["ghcr.io/test-org/app:latest"],
        },
    ])
    assert get_scan_sources_for_org("test-org") == []


def test_get_scan_sources_container_images_scan_scope_all_ignores_exclusions(monkeypatch):
    import src.shared.config as config
    from src.shared.config import get_scan_sources_for_org

    monkeypatch.setattr(config, "_read_source_connections", lambda: [
        {
            "id": "src_1", "category": "container-images", "sourceType": "ghcr",
            "name": "GHCR", "auth": {"orgOrOwner": "test-org", "token": "ghp_test"},
            "scanScope": "all", "excludedItems": ["ghcr.io/test-org/old:latest"],
            "syncSchedule": "6h", "status": "connected",
            "createdAt": "2026-01-01T00:00:00Z", "updatedAt": "2026-01-01T00:00:00Z",
            "discoveredItems": ["ghcr.io/test-org/app:latest", "ghcr.io/test-org/old:latest"],
        },
    ])
    sources = get_scan_sources_for_org("test-org")
    images = sources[0].container_images
    assert len(images) == 2  # scanScope "all" ignores exclusions


def test_org_has_source_connections_true(monkeypatch):
    import src.shared.config as config
    from src.shared.config import org_has_source_connections

    monkeypatch.setattr(config, "_read_source_connections", lambda: [
        {
            "id": "src_1", "category": "code-repositories", "sourceType": "github",
            "name": "GitHub", "auth": {"orgOrOwner": "test-org", "token": "ghp_test"},
            "scanScope": "all", "excludedItems": [], "syncSchedule": "6h",
            "status": "connected",
            "createdAt": "2026-01-01T00:00:00Z", "updatedAt": "2026-01-01T00:00:00Z",
            "discoveredItems": ["app"],
        },
    ])
    assert org_has_source_connections("test-org") is True


def test_org_has_source_connections_false_no_connections(monkeypatch):
    import src.shared.config as config
    from src.shared.config import org_has_source_connections

    monkeypatch.setattr(config, "_read_source_connections", lambda: [])
    assert org_has_source_connections("test-org") is False


def test_org_has_source_connections_false_no_token(monkeypatch):
    import src.shared.config as config
    from src.shared.config import org_has_source_connections

    monkeypatch.setattr(config, "_read_source_connections", lambda: [
        {
            "id": "src_1", "category": "code-repositories", "sourceType": "github",
            "name": "GitHub", "auth": {"orgOrOwner": "test-org"},
            "scanScope": "all", "excludedItems": [], "syncSchedule": "6h",
            "status": "connected",
            "createdAt": "2026-01-01T00:00:00Z", "updatedAt": "2026-01-01T00:00:00Z",
            "discoveredItems": ["app"],
        },
    ])
    assert org_has_source_connections("test-org") is False


def test_org_has_source_connections_false_not_connected(monkeypatch):
    import src.shared.config as config
    from src.shared.config import org_has_source_connections

    monkeypatch.setattr(config, "_read_source_connections", lambda: [
        {
            "id": "src_1", "category": "code-repositories", "sourceType": "github",
            "name": "GitHub", "auth": {"orgOrOwner": "test-org", "token": "ghp_test"},
            "scanScope": "all", "excludedItems": [], "syncSchedule": "6h",
            "status": "error",
            "createdAt": "2026-01-01T00:00:00Z", "updatedAt": "2026-01-01T00:00:00Z",
            "discoveredItems": ["app"],
        },
    ])
    assert org_has_source_connections("test-org") is False
