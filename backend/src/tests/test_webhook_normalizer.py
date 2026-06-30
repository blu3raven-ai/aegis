"""Coverage for the GitHub/GitLab/Bitbucket webhook normalizers.

These pure transforms sit at the SCM ingest boundary and decide the org_id,
repo_id, refs, and commit attribution every downstream scan keys on. A mis-parse
silently attributes a push to the wrong repo or drops the head SHA. Jenkins and
Azure normalizers already have their own tests; this covers the rest.
"""
from __future__ import annotations

from src.connectors.webhooks.normalizer import (
    normalize_bitbucket_pr,
    normalize_bitbucket_push,
    normalize_github_pr,
    normalize_github_push,
    normalize_gitlab_mr,
    normalize_gitlab_push,
)


# ── GitHub ───────────────────────────────────────────────────────────────────

def test_github_push_extracts_owner_repo_refs_and_commits():
    ev = normalize_github_push(
        {
            "repository": {"name": "widgets", "owner": {"login": "acme-org"}},
            "ref": "refs/heads/main",
            "before": "aaa",
            "after": "bbb",
            "commits": [{"id": "c1", "author": {"email": "dev@acme.test"}}],
        }
    )
    assert ev.org_id == "acme-org"
    assert ev.source_component == "integrations.github"
    assert ev.payload["repo_id"] == "acme-org/widgets"
    assert ev.payload["ref"] == "refs/heads/main"
    assert ev.payload["before_sha"] == "aaa"
    assert ev.payload["after_sha"] == "bbb"
    assert ev.payload["commits"] == [{"sha": "c1", "author": "dev@acme.test"}]


def test_github_pr_opened_vs_updated_type_and_fields():
    payload = {
        "repository": {"name": "widgets", "owner": {"login": "acme-org"}},
        "pull_request": {
            "number": 7,
            "base": {"sha": "base1"},
            "head": {"sha": "head1"},
            "user": {"login": "dev"},
            "title": "Add thing",
        },
    }
    opened = normalize_github_pr(payload, opened=True)
    updated = normalize_github_pr(payload, opened=False)
    assert type(opened).__name__ == "PrOpenedEvent"
    assert type(updated).__name__ == "PrUpdatedEvent"
    assert opened.payload["pr_number"] == 7
    assert opened.payload["base_sha"] == "base1"
    assert opened.payload["head_sha"] == "head1"
    assert opened.payload["author"] == "dev"
    assert opened.payload["title"] == "Add thing"


# ── GitLab ───────────────────────────────────────────────────────────────────

def test_gitlab_push_org_is_top_level_namespace():
    ev = normalize_gitlab_push(
        {
            "project": {"path_with_namespace": "acme-group/sub/widgets"},
            "ref": "refs/heads/main",
            "before": "x",
            "after": "y",
            "commits": [{"id": "g1", "author": {"email": "g@acme.test"}}],
        }
    )
    # repo_id keeps the full namespace; org_id is just the top-level group.
    assert ev.payload["repo_id"] == "acme-group/sub/widgets"
    assert ev.org_id == "acme-group"
    assert ev.payload["commits"] == [{"sha": "g1", "author": "g@acme.test"}]


def test_gitlab_mr_prefers_primary_sha_fields():
    ev = normalize_gitlab_mr(
        {
            "project": {"path_with_namespace": "acme-group/widgets"},
            "user": {"username": "dev"},
            "object_attributes": {
                "iid": 12,
                "merge_commit_sha": "merge1",
                "last_commit": {"id": "head1"},
                "diff_refs": {"base_sha": "diffbase", "head_sha": "diffhead"},
                "title": "MR title",
            },
        },
        opened=True,
    )
    assert ev.payload["pr_number"] == 12
    # merge_commit_sha and last_commit.id win over diff_refs.
    assert ev.payload["base_sha"] == "merge1"
    assert ev.payload["head_sha"] == "head1"
    assert ev.payload["author"] == "dev"


def test_gitlab_mr_falls_back_to_diff_refs():
    ev = normalize_gitlab_mr(
        {
            "project": {"path_with_namespace": "acme-group/widgets"},
            "object_attributes": {
                "iid": 13,
                "diff_refs": {"base_sha": "diffbase", "head_sha": "diffhead"},
                "title": "MR",
            },
        },
        opened=False,
    )
    assert type(ev).__name__ == "PrUpdatedEvent"
    # No merge_commit_sha / last_commit → diff_refs values fill in.
    assert ev.payload["base_sha"] == "diffbase"
    assert ev.payload["head_sha"] == "diffhead"
    assert ev.payload["author"] == ""  # missing user → empty


# ── Bitbucket ────────────────────────────────────────────────────────────────

def test_bitbucket_push_parses_changes_and_author_email():
    ev = normalize_bitbucket_push(
        {
            "repository": {"full_name": "workspace/widgets"},
            "push": {
                "changes": [
                    {
                        "new": {"name": "main", "target": {"hash": "after1"}},
                        "old": {"target": {"hash": "before1"}},
                        "commits": [
                            {"hash": "c1", "author": {"raw": "Dev Name <dev@acme.test>"}},
                        ],
                    }
                ]
            },
        }
    )
    assert ev.org_id == "workspace"
    assert ev.payload["repo_id"] == "workspace/widgets"
    assert ev.payload["ref"] == "main"
    assert ev.payload["after_sha"] == "after1"
    assert ev.payload["before_sha"] == "before1"
    # author.raw "Display <email>" is reduced to the bare email.
    assert ev.payload["commits"] == [{"sha": "c1", "author": "dev@acme.test"}]


def test_bitbucket_push_with_no_changes_is_empty_but_valid():
    ev = normalize_bitbucket_push({"repository": {"full_name": "ws/repo"}, "push": {"changes": []}})
    assert ev.payload["ref"] is None
    assert ev.payload["after_sha"] is None
    assert ev.payload["commits"] == []


def test_bitbucket_pr_maps_source_destination_and_type():
    payload = {
        "repository": {"full_name": "workspace/widgets"},
        "pullrequest": {
            "id": 9,
            "title": "Fix",
            "author": {"nickname": "dev"},
            "source": {"commit": {"hash": "head1"}},
            "destination": {"commit": {"hash": "base1"}},
        },
    }
    opened = normalize_bitbucket_pr(payload, opened=True)
    updated = normalize_bitbucket_pr(payload, opened=False)
    assert type(opened).__name__ == "PrOpenedEvent"
    assert type(updated).__name__ == "PrUpdatedEvent"
    assert opened.payload["pr_number"] == 9
    assert opened.payload["head_sha"] == "head1"
    assert opened.payload["base_sha"] == "base1"
    assert opened.payload["author"] == "dev"
