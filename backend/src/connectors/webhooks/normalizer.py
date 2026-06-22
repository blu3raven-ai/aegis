"""Translate platform-specific SCM webhook payloads into internal code events.

Each normalizer takes a raw parsed JSON dict from the provider and returns
a typed Event that the durable bus understands. No I/O happens here — this
is pure transformation so it can be unit-tested without a running server.

References used:
- GitHub webhook events: https://docs.github.com/en/webhooks/webhook-events-and-payloads
- GitLab webhook events: https://docs.gitlab.com/ee/user/project/integrations/webhook_events.html
- Bitbucket webhook events: https://developer.atlassian.com/cloud/bitbucket/webhooks/
- Azure DevOps service hooks: https://learn.microsoft.com/en-us/azure/devops/service-hooks/events
- Jenkins Notification Plugin: https://plugins.jenkins.io/notification/
"""
from __future__ import annotations

from urllib.parse import urlparse

from src.shared.event_types.code import CodePushEvent, PrOpenedEvent, PrUpdatedEvent




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


# ── Azure DevOps ──────────────────────────────────────────────────────────────


def _azure_repo_id(repo: dict) -> str:
    """Build a 2-segment ``project/repo`` from an Azure DevOps ``resource.repository`` block.

    Service-hook payloads do not reliably carry the org/account segment:
    ``resourceContainers.account`` is absent or unstable across event kinds, so
    we cannot synthesize a 3-segment ``org/project/repo`` form here. The
    normalizer therefore emits ``project.name`` + ``repository.name`` and the
    listener consumes it as ``owner=project, name=repo``. The resulting
    ``azure_devops:<project>/<repo>`` external_ref matches what asset
    registration uses for ADO sources.
    """
    project = (repo.get("project") or {}).get("name", "")
    name = repo.get("name", "")
    if project and name:
        return f"{project}/{name}"
    return name


def normalize_azure_push(payload: dict) -> CodePushEvent:
    resource = payload.get("resource", {})
    repo = resource.get("repository", {})
    repo_id = _azure_repo_id(repo)
    org_id = (repo.get("project") or {}).get("name", "") or repo.get("name", "")

    ref_updates = resource.get("refUpdates") or []
    first_update = ref_updates[0] if ref_updates else {}
    ref = first_update.get("name")
    after_sha = first_update.get("newObjectId")
    before_sha = first_update.get("oldObjectId")
    # Azure DevOps uses an all-zero SHA for branch creation; surface it as None
    # so the listener treats new-branch pushes the same way it does for other
    # providers (skip duplicate-of-nothing checks).
    if before_sha == "0" * 40:
        before_sha = None

    commits: list[dict] = []
    for commit in resource.get("commits") or []:
        author_email = ((commit.get("author") or {}).get("email")) or ""
        commits.append({"sha": commit.get("commitId"), "author": author_email})

    return CodePushEvent(
        org_id=org_id,
        source_component="integrations.azure_devops",
        payload={
            "repo_id": repo_id,
            "ref": ref,
            "before_sha": before_sha,
            "after_sha": after_sha,
            "commits": commits,
            "author": (resource.get("pushedBy") or {}).get("uniqueName", ""),
        },
    )


def normalize_azure_pr(payload: dict, *, opened: bool) -> PrOpenedEvent | PrUpdatedEvent:
    resource = payload.get("resource", {})
    repo = resource.get("repository", {})
    repo_id = _azure_repo_id(repo)
    org_id = (repo.get("project") or {}).get("name", "") or repo.get("name", "")
    EventCls = PrOpenedEvent if opened else PrUpdatedEvent
    return EventCls(
        org_id=org_id,
        source_component="integrations.azure_devops",
        payload={
            "repo_id": repo_id,
            "pr_number": resource.get("pullRequestId"),
            "base_sha": (resource.get("lastMergeTargetCommit") or {}).get("commitId"),
            "head_sha": (resource.get("lastMergeSourceCommit") or {}).get("commitId"),
            "author": (resource.get("createdBy") or {}).get("uniqueName", ""),
            "title": resource.get("title"),
            "source_ref": resource.get("sourceRefName"),
            "target_ref": resource.get("targetRefName"),
        },
    )


# ── Jenkins ───────────────────────────────────────────────────────────────────


def _jenkins_host(full_url: str | None) -> str:
    """Extract the Jenkins controller host from the build's ``full_url``.

    The controller host is the identity boundary for a Jenkins source: two
    jobs with the same ``name`` on different controllers must not collide.
    A malformed URL returns an empty string so the caller can fall back to
    the bare job name and let the operator register the source that way.
    """
    if not full_url:
        return ""
    try:
        return urlparse(full_url).netloc or ""
    except (ValueError, TypeError):
        return ""


def _jenkins_repo_id(payload: dict) -> str:
    """Compose ``<controller_host>/<job_name>`` from a Notification Plugin payload.

    Jenkins is not an SCM, so the canonical identity for a Jenkins-backed
    asset is the controller + job pair rather than ``owner/repo``. The
    nested folder path inside ``name`` (e.g. ``folder/sub/my-pipeline``)
    is preserved verbatim so the listener's ``rpartition`` split keeps
    the trailing job-name segment.
    """
    job_name = (payload.get("name") or "").strip()
    full_url = (payload.get("build") or {}).get("full_url")
    host = _jenkins_host(full_url)
    if host and job_name:
        return f"{host}/{job_name}"
    return job_name


def _jenkins_ref(branch: str | None) -> str | None:
    """Normalize Jenkins' git plugin branch string to a canonical ``refs/...`` ref.

    The git plugin emits ``origin/<branch>`` for the default remote and the
    raw ref for tags / detached HEAD. Strip the default ``origin/`` prefix so
    the listener's ``_parse_branch_from_ref`` round-trips back to the bare
    branch name; pass through anything already starting with ``refs/`` so a
    tag build remains identifiable as a tag.
    """
    if not branch:
        return None
    if branch.startswith("refs/"):
        return branch
    if branch.startswith("origin/"):
        branch = branch[len("origin/"):]
    return f"refs/heads/{branch}"


def normalize_jenkins_build(payload: dict) -> CodePushEvent:
    """Translate a Jenkins Notification Plugin payload into a ``code.push`` event.

    Jenkins does not carry a meaningful actor on Notification Plugin
    payloads (the plugin emits build-state changes, not user actions), so
    no ``author`` field is published — the listener's audit row will omit
    it the same way it omits any other None metadata.
    """
    build = payload.get("build") or {}
    scm = build.get("scm") or {}
    repo_id = _jenkins_repo_id(payload)
    org_id = _jenkins_host((build.get("full_url"))) or repo_id

    return CodePushEvent(
        org_id=org_id,
        source_component="integrations.jenkins",
        payload={
            "repo_id": repo_id,
            "ref": _jenkins_ref(scm.get("branch")),
            "before_sha": None,
            "after_sha": scm.get("commit") or None,
            "commits": [],
            "scm_url": scm.get("url"),
            "build_number": build.get("number"),
            "build_phase": build.get("phase"),
        },
    )
