"""Smoke tests for shared/config.py::get_scan_sources_for_org dispatching through the provider registry."""
from __future__ import annotations

import pytest


def test_container_scanner_config_defaults_nvd_on(monkeypatch):
    """Container NVD enrichment defaults on, matching the dependencies scanner."""
    from src.shared import config as cfg
    monkeypatch.setattr(cfg, "read_app_config", lambda: {"tools": {"container_scanning": {}}})
    out = cfg.get_container_scanner_config()
    assert out["nvdEnabled"] == "true"
    assert out["ghsaEnabled"] == "false"


@pytest.fixture
def _patch_connections(monkeypatch):
    def _set(conns):
        monkeypatch.setattr("src.shared.config._read_source_connections", lambda: conns)
    return _set


def _conn(source_type: str, category: str, *, org: str = "acme", token: str = "t",
          instance_url: str = "", discovered: list[str] | None = None) -> dict:
    return {
        "id": f"c-{source_type}",
        "category": category,
        "sourceType": source_type,
        "status": "connected",
        "auth": {
            "orgOrOwner": org,
            "token": token,
            "instanceUrl": instance_url,
        },
        "discoveredItems": discovered or [],
        "scanScope": "all",
        "excludedItems": [],
    }


def test_get_scan_sources_dispatches_github_through_registry(_patch_connections):
    from src.shared.config import get_scan_sources_for_org
    _patch_connections([_conn("github", "code-repositories", discovered=["foo"])])
    sources = get_scan_sources_for_org("acme")
    assert len(sources) == 1
    assert sources[0].repo_urls == ["https://github.com/acme/foo.git"]


def test_get_scan_sources_dispatches_gitlab_with_instance_url(_patch_connections):
    from src.shared.config import get_scan_sources_for_org
    _patch_connections([
        _conn("gitlab", "code-repositories",
              instance_url="https://git.acme.io", discovered=["foo"]),
    ])
    sources = get_scan_sources_for_org("acme")
    assert sources[0].repo_urls == ["https://git.acme.io/acme/foo.git"]


def test_get_scan_sources_dispatches_bitbucket(_patch_connections):
    from src.shared.config import get_scan_sources_for_org
    _patch_connections([_conn("bitbucket", "code-repositories", discovered=["foo"])])
    sources = get_scan_sources_for_org("acme")
    assert sources[0].repo_urls == ["https://bitbucket.org/acme/foo.git"]


def test_get_scan_sources_dispatches_ghcr(_patch_connections):
    from src.shared.config import get_scan_sources_for_org
    _patch_connections([_conn("ghcr", "container-images", discovered=["img:v1"])])
    sources = get_scan_sources_for_org("acme")
    assert sources[0].container_images == ["ghcr.io/acme/img:v1"]


def test_get_scan_sources_dispatches_gcr_with_default(_patch_connections):
    from src.shared.config import get_scan_sources_for_org
    _patch_connections([_conn("gcr", "container-images", discovered=["img:v1"])])
    sources = get_scan_sources_for_org("acme")
    assert sources[0].container_images == ["gcr.io/acme/img:v1"]


def test_get_scan_sources_skips_unknown_source_type(_patch_connections):
    from src.shared.config import get_scan_sources_for_org
    _patch_connections([_conn("totally-fake-scm", "code-repositories", discovered=["foo"])])
    sources = get_scan_sources_for_org("acme")
    # No source emitted — the only connection's source_type isn't registered
    assert sources == []




def test_get_scan_sources_selected_scope_uses_included_items(_patch_connections):
    """A cherry-pick connection resolves only its included repos, not all discovered."""
    from src.shared.config import get_scan_sources_for_org
    conn = _conn("github", "code-repositories", discovered=["acme/foo", "acme/bar"])
    conn["scanScope"] = "selected"
    conn["includedItems"] = ["acme/foo"]
    _patch_connections([conn])
    sources = get_scan_sources_for_org("acme")
    assert len(sources) == 1
    assert sources[0].repo_urls == ["https://github.com/acme/foo.git"]
