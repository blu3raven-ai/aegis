"""Pure unit tests for integrations.normalizer — no I/O, no HTTP."""
from __future__ import annotations

import pytest

from src.integrations.normalizer import (
    normalize_bitbucket_pr,
    normalize_bitbucket_push,
    normalize_github_pr,
    normalize_github_push,
    normalize_gitlab_mr,
    normalize_gitlab_push,
)
from src.shared.event_types.code import CodePushEvent, PrOpenedEvent, PrUpdatedEvent


# ── Sample payloads ───────────────────────────────────────────────────────────

GITHUB_PUSH = {
    "ref": "refs/heads/main",
    "before": "abc123",
    "after": "def456",
    "repository": {
        "name": "security-portal",
        "owner": {"login": "acme-org"},
    },
    "commits": [
        {"id": "def456", "author": {"email": "dev@acme-org.example.com"}},
    ],
}

GITHUB_PR = {
    "action": "opened",
    "repository": {
        "name": "security-portal",
        "owner": {"login": "acme-org"},
    },
    "pull_request": {
        "number": 42,
        "title": "Add rate limiting",
        "user": {"login": "dev-user"},
        "base": {"sha": "base000"},
        "head": {"sha": "head111"},
    },
}

GITLAB_PUSH = {
    "object_kind": "push",
    "ref": "refs/heads/main",
    "before": "aaa",
    "after": "bbb",
    "project": {"path_with_namespace": "acme-org/security-portal"},
    "commits": [
        {"id": "bbb", "author": {"email": "dev@acme-org.example.com"}},
    ],
}

GITLAB_MR = {
    "object_kind": "merge_request",
    "user": {"username": "dev-user"},
    "project": {"path_with_namespace": "acme-org/security-portal"},
    "object_attributes": {
        "iid": 7,
        "title": "Fix SQL injection",
        "state": "opened",
        "action": "open",
        "diff_refs": {
            "base_sha": "base000",
            "head_sha": "head111",
        },
    },
}

BITBUCKET_PUSH = {
    "repository": {"full_name": "acme-org/security-portal"},
    "push": {
        "changes": [
            {
                "new": {
                    "name": "main",
                    "target": {"hash": "def456"},
                },
                "old": {
                    "target": {"hash": "abc123"},
                },
                "commits": [
                    {
                        "hash": "def456",
                        "author": {"raw": "Dev User <dev@acme-org.example.com>"},
                    }
                ],
            }
        ]
    },
}

BITBUCKET_PR = {
    "repository": {"full_name": "acme-org/security-portal"},
    "pullrequest": {
        "id": 5,
        "title": "Upgrade deps",
        "author": {"nickname": "dev-user"},
        "source": {"commit": {"hash": "head222"}},
        "destination": {"commit": {"hash": "base111"}},
    },
}


# ── GitHub ────────────────────────────────────────────────────────────────────


def test_normalize_github_push_type():
    event = normalize_github_push(GITHUB_PUSH)
    assert isinstance(event, CodePushEvent)


def test_normalize_github_push_fields():
    event = normalize_github_push(GITHUB_PUSH)
    assert event.org_id == "acme-org"
    assert event.source_component == "integrations.github"
    assert event.payload["repo_id"] == "acme-org/security-portal"
    assert event.payload["ref"] == "refs/heads/main"
    assert event.payload["before_sha"] == "abc123"
    assert event.payload["after_sha"] == "def456"
    assert event.payload["commits"][0]["sha"] == "def456"
    assert event.payload["commits"][0]["author"] == "dev@acme-org.example.com"


def test_normalize_github_pr_opened():
    event = normalize_github_pr(GITHUB_PR, opened=True)
    assert isinstance(event, PrOpenedEvent)
    assert event.payload["pr_number"] == 42
    assert event.payload["author"] == "dev-user"
    assert event.payload["base_sha"] == "base000"
    assert event.payload["head_sha"] == "head111"


def test_normalize_github_pr_updated():
    event = normalize_github_pr(GITHUB_PR, opened=False)
    assert isinstance(event, PrUpdatedEvent)
    assert event.payload["title"] == "Add rate limiting"


def test_normalize_github_push_no_commits():
    payload = {**GITHUB_PUSH, "commits": []}
    event = normalize_github_push(payload)
    assert event.payload["commits"] == []


# ── GitLab ────────────────────────────────────────────────────────────────────


def test_normalize_gitlab_push_type():
    event = normalize_gitlab_push(GITLAB_PUSH)
    assert isinstance(event, CodePushEvent)


def test_normalize_gitlab_push_fields():
    event = normalize_gitlab_push(GITLAB_PUSH)
    assert event.org_id == "acme-org"
    assert event.source_component == "integrations.gitlab"
    assert event.payload["repo_id"] == "acme-org/security-portal"
    assert event.payload["ref"] == "refs/heads/main"
    assert event.payload["before_sha"] == "aaa"
    assert event.payload["after_sha"] == "bbb"


def test_normalize_gitlab_mr_opened():
    event = normalize_gitlab_mr(GITLAB_MR, opened=True)
    assert isinstance(event, PrOpenedEvent)
    assert event.payload["pr_number"] == 7
    assert event.payload["author"] == "dev-user"
    assert event.payload["title"] == "Fix SQL injection"


def test_normalize_gitlab_mr_updated():
    event = normalize_gitlab_mr(GITLAB_MR, opened=False)
    assert isinstance(event, PrUpdatedEvent)


def test_normalize_gitlab_push_no_slash_in_namespace():
    """Handles edge case where namespace has no group prefix."""
    payload = {**GITLAB_PUSH, "project": {"path_with_namespace": "solo-repo"}}
    event = normalize_gitlab_push(payload)
    assert event.org_id == "solo-repo"


# ── Bitbucket ─────────────────────────────────────────────────────────────────


def test_normalize_bitbucket_push_type():
    event = normalize_bitbucket_push(BITBUCKET_PUSH)
    assert isinstance(event, CodePushEvent)


def test_normalize_bitbucket_push_fields():
    event = normalize_bitbucket_push(BITBUCKET_PUSH)
    assert event.org_id == "acme-org"
    assert event.source_component == "integrations.bitbucket"
    assert event.payload["repo_id"] == "acme-org/security-portal"
    assert event.payload["ref"] == "main"
    assert event.payload["before_sha"] == "abc123"
    assert event.payload["after_sha"] == "def456"
    assert event.payload["commits"][0]["sha"] == "def456"
    assert event.payload["commits"][0]["author"] == "dev@acme-org.example.com"


def test_normalize_bitbucket_pr_opened():
    event = normalize_bitbucket_pr(BITBUCKET_PR, opened=True)
    assert isinstance(event, PrOpenedEvent)
    assert event.payload["pr_number"] == 5
    assert event.payload["author"] == "dev-user"
    assert event.payload["base_sha"] == "base111"
    assert event.payload["head_sha"] == "head222"


def test_normalize_bitbucket_pr_updated():
    event = normalize_bitbucket_pr(BITBUCKET_PR, opened=False)
    assert isinstance(event, PrUpdatedEvent)
    assert event.payload["title"] == "Upgrade deps"


def test_normalize_bitbucket_push_empty_changes():
    payload = {**BITBUCKET_PUSH, "push": {"changes": []}}
    event = normalize_bitbucket_push(payload)
    assert event.payload["commits"] == []
    assert event.payload["ref"] is None
