"""Ingest scope filter — a rogue runner can't plant findings/SBOMs on assets
it wasn't asked to scan.

The filter matches a finding's repo (or an SBOM's image) against the job's
assigned scope (GIT_REPOS / DOCKER_IMAGES). These tests pin the shared helper
and assert every repo-scanner wires its assigned scope into the ScanContext so
the filter cannot be silently skipped by a new scanner.
"""
from __future__ import annotations

from pathlib import Path

from src.shared.lifecycle import in_assigned_scope


def test_no_assigned_scope_allows_everything():
    # No scope enforced (manual scan, or scope resolution returned nothing) —
    # the filter is skipped, matching the original findings-filter semantics.
    assert in_assigned_scope("acme/anything", None) is True
    assert in_assigned_scope("acme/anything", []) is True


def test_empty_name_allowed():
    # A finding with no extractable repo is not dropped by the scope filter
    # (matches the original `if assigned and repo:` guard).
    assert in_assigned_scope("", ["https://github.com/acme/app"]) is True
    assert in_assigned_scope(None, ["https://github.com/acme/app"]) is True


def test_assigned_scope_tail_matches_clone_url():
    # GIT_REPOS are clone URLs; findings carry owner/repo. Tail-match so they
    # line up without parsing the URL.
    assigned = ["https://github.com/acme/app"]
    assert in_assigned_scope("acme/app", assigned) is True
    assert in_assigned_scope("acme/other", assigned) is False


def test_assigned_scope_matches_image_ref():
    # DOCKER_IMAGES carry a tag; the SBOM component.name and the finding repo
    # may or may not. Compared tag-stripped so they line up either way.
    assert in_assigned_scope("acme/app:1.0", ["acme/app:1.0"]) is True
    assert in_assigned_scope("acme/app", ["acme/app"]) is True
    assert in_assigned_scope("evilcorp/app:latest", ["acme/app:1.0"]) is False


_REPO_SCANNERS = [
    "backend/src/agent_scanning/scanner.py",
    "backend/src/code_scanning/scanner.py",
    "backend/src/dependencies/scanner.py",
    "backend/src/iac/scanner.py",
    "backend/src/secrets/scanner.py",
]


def test_every_repo_scanner_wires_assigned_scope():
    # Regression for the asymmetry where only some scanners passed git_repos
    # into their ScanContext, letting a rogue runner plant findings on
    # out-of-scope repo assets. Every repo-scanner must resolve the assigned
    # scope and pass it through so apply_lifecycle can filter.
    root = Path(__file__).resolve().parents[2]
    missing: list[str] = []
    for rel in _REPO_SCANNERS:
        src = (root / rel).read_text()
        if "git_repos_for_run" not in src:
            missing.append(rel)
    assert not missing, f"repo scanners without git_repos_for_run: {missing}"


def test_container_scanner_wires_assigned_image_scope():
    # The container scanner's assigned scope is DOCKER_IMAGES, not GIT_REPOS.
    # The SBOM ingest consults it; since container findings are derived from
    # the scoped asset dict, that check covers both stores.
    root = Path(__file__).resolve().parents[2]
    src = (root / "backend/src/containers/scanner.py").read_text()
    assert "docker_images_for_run" in src
    assert "_image_name" in src  # tag-stripped so tagless SBOMs match
