"""Concrete RepoProvider implementations.

Each class encapsulates one SCM's clone-URL convention. Adding a new SCM:
write a class with a `source_type` attribute and a `clone_url` method, then
register it at the bottom of this file.
"""
from __future__ import annotations

from src.shared.providers.base import register_repo_provider


class GitHubRepoProvider:
    source_type = "github"

    def clone_url(self, org: str, repo: str, instance_url: str) -> str:
        # GitHub Enterprise honors instance_url; SaaS uses github.com
        base = instance_url.rstrip("/") if instance_url else "https://github.com"
        return f"{base}/{org}/{repo}.git"


class GitLabRepoProvider:
    source_type = "gitlab"

    def clone_url(self, org: str, repo: str, instance_url: str) -> str:
        base = instance_url.rstrip("/") if instance_url else "https://gitlab.com"
        return f"{base}/{org}/{repo}.git"


class BitbucketRepoProvider:
    source_type = "bitbucket"

    def clone_url(self, org: str, repo: str, instance_url: str) -> str:
        base = instance_url.rstrip("/") if instance_url else "https://bitbucket.org"
        return f"{base}/{org}/{repo}.git"


class GiteaRepoProvider:
    source_type = "gitea"

    def clone_url(self, org: str, repo: str, instance_url: str) -> str:
        base = instance_url.rstrip("/") if instance_url else "https://gitea.com"
        return f"{base}/{org}/{repo}.git"


for _cls in (GitHubRepoProvider, GitLabRepoProvider, BitbucketRepoProvider, GiteaRepoProvider):
    register_repo_provider(_cls())
