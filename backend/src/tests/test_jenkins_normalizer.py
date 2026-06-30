"""Coverage for the Jenkins webhook normalizer and its URL/ref helpers.

Jenkins is not an SCM, so identity is the controller host + job pair, and the
git-plugin branch string needs canonicalizing to a refs/... ref. These parsers
decide asset identity and branch attribution; the existing Jenkins test only
exercises the ingester's test() probe, not this transform.
"""
from __future__ import annotations

import pytest

from src.connectors.webhooks.normalizer import (
    _jenkins_host,
    _jenkins_ref,
    _jenkins_repo_id,
    normalize_jenkins_build,
)


# ── _jenkins_host ────────────────────────────────────────────────────────────

def test_jenkins_host_returns_netloc():
    assert _jenkins_host("https://ci.acme.test:8080/job/build/12/") == "ci.acme.test:8080"


@pytest.mark.parametrize("value", [None, ""])
def test_jenkins_host_empty_input_returns_empty(value):
    assert _jenkins_host(value) == ""


def test_jenkins_host_no_netloc_returns_empty():
    # A bare path with no scheme/host yields no netloc.
    assert _jenkins_host("not-a-url") == ""


# ── _jenkins_repo_id ─────────────────────────────────────────────────────────

def test_jenkins_repo_id_combines_host_and_job():
    payload = {"name": "folder/sub/pipeline", "build": {"full_url": "https://ci.acme.test/job/x/1/"}}
    assert _jenkins_repo_id(payload) == "ci.acme.test/folder/sub/pipeline"


def test_jenkins_repo_id_falls_back_to_job_name_without_host():
    assert _jenkins_repo_id({"name": "pipeline", "build": {}}) == "pipeline"


def test_jenkins_repo_id_strips_whitespace():
    assert _jenkins_repo_id({"name": "  pipeline  ", "build": {}}) == "pipeline"


# ── _jenkins_ref ─────────────────────────────────────────────────────────────

def test_jenkins_ref_none_passes_through():
    assert _jenkins_ref(None) is None


def test_jenkins_ref_strips_origin_prefix():
    assert _jenkins_ref("origin/main") == "refs/heads/main"


def test_jenkins_ref_bare_branch_gets_heads_prefix():
    assert _jenkins_ref("feature-x") == "refs/heads/feature-x"


def test_jenkins_ref_existing_refs_passes_through():
    # A tag / explicit ref must remain identifiable, not be re-prefixed.
    assert _jenkins_ref("refs/tags/v1.0") == "refs/tags/v1.0"


# ── normalize_jenkins_build ──────────────────────────────────────────────────

def test_normalize_jenkins_build_full_payload():
    ev = normalize_jenkins_build(
        {
            "name": "pipeline",
            "build": {
                "full_url": "https://ci.acme.test/job/pipeline/42/",
                "number": 42,
                "phase": "COMPLETED",
                "scm": {"branch": "origin/main", "commit": "deadbeef", "url": "git@x:acme/repo.git"},
            },
        }
    )
    assert ev.org_id == "ci.acme.test"
    assert ev.source_component == "integrations.jenkins"
    assert ev.payload["repo_id"] == "ci.acme.test/pipeline"
    assert ev.payload["ref"] == "refs/heads/main"
    assert ev.payload["after_sha"] == "deadbeef"
    assert ev.payload["before_sha"] is None
    assert ev.payload["commits"] == []
    assert ev.payload["build_number"] == 42
    assert ev.payload["build_phase"] == "COMPLETED"
    assert ev.payload["scm_url"] == "git@x:acme/repo.git"


def test_normalize_jenkins_build_without_host_uses_repo_id_as_org():
    # No full_url → host is empty → org_id falls back to the bare job name.
    ev = normalize_jenkins_build({"name": "pipeline", "build": {"scm": {"branch": "main"}}})
    assert ev.org_id == "pipeline"
    assert ev.payload["repo_id"] == "pipeline"
    assert ev.payload["ref"] == "refs/heads/main"
    assert ev.payload["after_sha"] is None


def test_normalize_jenkins_build_empty_scm_yields_null_ref_and_sha():
    ev = normalize_jenkins_build({"name": "p", "build": {"full_url": "https://ci.test/x/1/"}})
    assert ev.payload["ref"] is None
    assert ev.payload["after_sha"] is None
    assert ev.payload["scm_url"] is None
