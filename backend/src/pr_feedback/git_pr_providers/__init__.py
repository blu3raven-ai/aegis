"""SCM-specific PR comment providers."""
from typing import Any

from .azure_devops import AzureDevOpsPrProvider
from .base import GitPrProvider
from .bitbucket import BitbucketPrProvider
from .github import GitHubPrProvider
from .gitlab import GitLabPrProvider


def resolve_pr_provider(source: Any) -> GitPrProvider | None:
    """Pick the right PR provider for the source's SCM type. None if unknown."""
    scm = getattr(source, "scm_type", None)
    if scm == "github":
        return GitHubPrProvider()
    if scm == "gitlab":
        base = getattr(source, "scm_base_url", None)
        return GitLabPrProvider(base_url=base) if base else GitLabPrProvider()
    if scm == "bitbucket":
        return BitbucketPrProvider()
    if scm == "azure_devops":
        return AzureDevOpsPrProvider()
    return None


__all__ = (
    "GitPrProvider",
    "GitHubPrProvider",
    "GitLabPrProvider",
    "BitbucketPrProvider",
    "AzureDevOpsPrProvider",
    "resolve_pr_provider",
)
