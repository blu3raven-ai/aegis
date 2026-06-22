"""Canonical external_ref construction for assets.

Single source of truth for asset identity strings. All three ingestion paths
(source-connection discovery, manual upload, BYO import) must produce the
same string for the same real-world thing — that string is the merge boundary
in the `assets.external_ref` unique constraint.
"""
from __future__ import annotations

_REPO_SOURCE_TYPES = frozenset({"github", "gitlab", "bitbucket", "gitea", "azure_devops", "jenkins"})
_IMAGE_REGISTRIES = frozenset({"ghcr", "dockerhub", "ecr", "gcr", "acr", "gitlab-registry"})
# Source-connection registry tokens that normalise onto a canonical registry.
_IMAGE_REGISTRY_ALIASES = {"docker-hub": "dockerhub"}


def repo_ref(source_type: str, owner: str, name: str) -> str:
    """Canonical key for a code repository.

    Jenkins is not an SCM, but the webhook pipeline needs a canonical
    identity for a Jenkins-backed asset so it can be looked up by
    ``external_ref``. The accepted shape is
    ``jenkins:<controller_host>/<job_name>`` — ``owner`` is the controller
    host and ``name`` is the (possibly folder-pathed) job name."""
    st = source_type.strip().lower()
    if st not in _REPO_SOURCE_TYPES:
        raise ValueError(f"unknown source_type: {source_type!r}")
    o = owner.strip()
    if not o:
        raise ValueError("owner is required")
    n = name.strip()
    if not n:
        raise ValueError("name is required")
    return f"{st}:{o}/{n}"


def image_ref(registry: str, image: str, tag: str) -> str:
    """Canonical key for a container image (tag defaults to 'latest').

    Accepts source-connection registry tokens (e.g. ``docker-hub``) and
    normalises them to the canonical registry so the same registry always
    yields the same external_ref.
    """
    r = registry.strip().lower()
    r = _IMAGE_REGISTRY_ALIASES.get(r, r)
    if r not in _IMAGE_REGISTRIES:
        raise ValueError(f"unknown registry: {registry!r}")
    i = image.strip()
    if not i:
        raise ValueError("image is required")
    t = tag.strip() or "latest"
    return f"{r}:{i}:{t}"


def owner_from_external_ref(external_ref: str) -> str:
    """Return the owner segment of a canonical external_ref.

    For "github:acme/foo" returns "acme". For "ghcr:acme/img:tag" returns "acme".
    Raises ValueError if the format is unrecognized.
    """
    if ":" not in external_ref:
        raise ValueError(f"unrecognized external_ref: {external_ref!r}")
    _source, rest = external_ref.split(":", 1)
    if "/" not in rest:
        raise ValueError(f"unrecognized external_ref: {external_ref!r}")
    owner, _name = rest.split("/", 1)
    return owner
