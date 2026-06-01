"""Translate platform-specific SCM webhook payloads into internal code events.

Each normalizer takes a raw parsed JSON dict from the provider and returns
a typed Event that the durable bus understands. No I/O happens here — this
is pure transformation so it can be unit-tested without a running server.

References used:
- GitHub webhook events: https://docs.github.com/en/webhooks/webhook-events-and-payloads
- GitLab webhook events: https://docs.gitlab.com/ee/user/project/integrations/webhook_events.html
- Bitbucket webhook events: https://developer.atlassian.com/cloud/bitbucket/webhooks/
"""
from __future__ import annotations

from src.shared.event_types.code import CodePushEvent, PrOpenedEvent, PrUpdatedEvent


# ── GitHub ────────────────────────────────────────────────────────────────────


def normalize_github_push(payload: dict) -> CodePushEvent:
    repo = payload["repository"]
    owner = repo["owner"]["login"]
    repo_id = f"{owner}/{repo['name']}"
    return CodePushEvent(
        org_id=owner,
        source_component="integrations.github",
        payload={
            "repo_id": repo_id,
            "ref": payload.get("ref"),
            "before_sha": payload.get("before"),
            "after_sha": payload.get("after"),
            "commits": [
                {"sha": c["id"], "author": c["author"]["email"]}
                for c in payload.get("commits", [])
            ],
        },
    )


def normalize_github_pr(payload: dict, *, opened: bool) -> PrOpenedEvent | PrUpdatedEvent:
    repo = payload["repository"]
    owner = repo["owner"]["login"]
    repo_id = f"{owner}/{repo['name']}"
    pr = payload["pull_request"]
    EventCls = PrOpenedEvent if opened else PrUpdatedEvent
    return EventCls(
        org_id=owner,
        source_component="integrations.github",
        payload={
            "repo_id": repo_id,
            "pr_number": pr["number"],
            "base_sha": pr["base"]["sha"],
            "head_sha": pr["head"]["sha"],
            "author": pr["user"]["login"],
            "title": pr["title"],
        },
    )


# ── GitLab ────────────────────────────────────────────────────────────────────


def normalize_gitlab_push(payload: dict) -> CodePushEvent:
    # GitLab push hook: project.path_with_namespace is "group/repo"
    project = payload.get("project", {})
    namespace = project.get("path_with_namespace", "")
    # org_id is the top-level namespace (group or user)
    org_id = namespace.split("/")[0] if "/" in namespace else namespace
    return CodePushEvent(
        org_id=org_id,
        source_component="integrations.gitlab",
        payload={
            "repo_id": namespace,
            "ref": payload.get("ref"),
            "before_sha": payload.get("before"),
            "after_sha": payload.get("after"),
            "commits": [
                {"sha": c["id"], "author": c["author"]["email"]}
                for c in payload.get("commits", [])
            ],
        },
    )


def normalize_gitlab_mr(payload: dict, *, opened: bool) -> PrOpenedEvent | PrUpdatedEvent:
    # GitLab merge_request hook wraps attributes under object_attributes
    project = payload.get("project", {})
    namespace = project.get("path_with_namespace", "")
    org_id = namespace.split("/")[0] if "/" in namespace else namespace
    attrs = payload.get("object_attributes", {})
    author_username = (payload.get("user") or {}).get("username", "")
    EventCls = PrOpenedEvent if opened else PrUpdatedEvent
    return EventCls(
        org_id=org_id,
        source_component="integrations.gitlab",
        payload={
            "repo_id": namespace,
            "pr_number": attrs.get("iid"),
            "base_sha": attrs.get("merge_commit_sha") or attrs.get("diff_refs", {}).get("base_sha"),
            "head_sha": attrs.get("last_commit", {}).get("id") or attrs.get("diff_refs", {}).get("head_sha"),
            "author": author_username,
            "title": attrs.get("title"),
        },
    )


# ── Bitbucket ─────────────────────────────────────────────────────────────────


def normalize_bitbucket_push(payload: dict) -> CodePushEvent:
    # Bitbucket repo:push: repository.full_name is "workspace/repo"
    repo = payload.get("repository", {})
    full_name = repo.get("full_name", "")
    org_id = full_name.split("/")[0] if "/" in full_name else full_name
    push = payload.get("push", {})
    changes = push.get("changes", [])

    commits: list[dict] = []
    ref = None
    before_sha = None
    after_sha = None

    if changes:
        first = changes[0]
        new_ref = first.get("new") or {}
        old_ref = first.get("old") or {}
        ref = new_ref.get("name")
        after_sha = (new_ref.get("target") or {}).get("hash")
        before_sha = (old_ref.get("target") or {}).get("hash")
        for change in changes:
            for commit in change.get("commits", []):
                author_raw = (commit.get("author") or {}).get("raw", "")
                # author.raw is "Display Name <email@example.com>"
                email = author_raw.split("<")[-1].rstrip(">") if "<" in author_raw else author_raw
                commits.append({"sha": commit.get("hash"), "author": email})

    return CodePushEvent(
        org_id=org_id,
        source_component="integrations.bitbucket",
        payload={
            "repo_id": full_name,
            "ref": ref,
            "before_sha": before_sha,
            "after_sha": after_sha,
            "commits": commits,
        },
    )


def normalize_bitbucket_pr(payload: dict, *, opened: bool) -> PrOpenedEvent | PrUpdatedEvent:
    repo = payload.get("repository", {})
    full_name = repo.get("full_name", "")
    org_id = full_name.split("/")[0] if "/" in full_name else full_name
    pr = payload.get("pullrequest", {})
    source = pr.get("source", {})
    dest = pr.get("destination", {})
    author = (pr.get("author") or {}).get("nickname", "")
    EventCls = PrOpenedEvent if opened else PrUpdatedEvent
    return EventCls(
        org_id=org_id,
        source_component="integrations.bitbucket",
        payload={
            "repo_id": full_name,
            "pr_number": pr.get("id"),
            "base_sha": (dest.get("commit") or {}).get("hash"),
            "head_sha": (source.get("commit") or {}).get("hash"),
            "author": author,
            "title": pr.get("title"),
        },
    )
