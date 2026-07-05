"""Provider strategy interfaces and registry.

A provider implements one piece of source_type-specific behavior. The
registry maps a `source_type` string (as stored on `SourceConnection.source_type`)
to a provider instance. Callers dispatch through `get_*` rather than
branching on `source_type` strings.
"""
from __future__ import annotations

from typing import Protocol


class UnknownProvider(LookupError):
    """Raised when no provider is registered for a given source_type."""


class RepoProvider(Protocol):
    """Provider for code-repository sources (SCM)."""

    source_type: str

    def clone_url(self, org: str, repo: str, instance_url: str) -> str:
        """Return a git clone URL for `<org>/<repo>`.

        `instance_url` is honored for self-hosted instances (e.g. enterprise GitLab).
        Pass empty string for SaaS defaults.
        """
        ...


class ImageRegistry(Protocol):
    """Provider for container-image registries."""

    source_type: str

    def normalize_image_ref(self, org: str, name: str, instance_url: str) -> str:
        """Return the fully-qualified image reference for `<org>/<name>`."""
        ...


_repo_providers: dict[str, RepoProvider] = {}
_image_registries: dict[str, ImageRegistry] = {}


def register_repo_provider(provider: RepoProvider) -> None:
    _repo_providers[provider.source_type] = provider


def register_image_registry(registry: ImageRegistry) -> None:
    _image_registries[registry.source_type] = registry


def get_repo_provider(source_type: str) -> RepoProvider:
    try:
        return _repo_providers[source_type]
    except KeyError:
        raise UnknownProvider(f"no repo provider registered for source_type={source_type!r}")


def get_image_registry(source_type: str) -> ImageRegistry:
    try:
        return _image_registries[source_type]
    except KeyError:
        raise UnknownProvider(f"no image registry registered for source_type={source_type!r}")
