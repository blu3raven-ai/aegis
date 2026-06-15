"""Provider resolver picks the right provider per source.scm_type."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.pr_feedback.git_pr_providers.azure_devops import AzureDevOpsPrProvider
from src.pr_feedback.git_pr_providers.bitbucket import BitbucketPrProvider
from src.pr_feedback.git_pr_providers.github import GitHubPrProvider
from src.pr_feedback.git_pr_providers.gitlab import GitLabPrProvider
from src.pr_feedback.poster import _resolve_pr_provider


def test_resolves_github():
    s = SimpleNamespace(scm_type="github")
    assert isinstance(_resolve_pr_provider(s), GitHubPrProvider)


def test_resolves_gitlab():
    s = SimpleNamespace(scm_type="gitlab")
    assert isinstance(_resolve_pr_provider(s), GitLabPrProvider)


def test_resolves_bitbucket():
    s = SimpleNamespace(scm_type="bitbucket")
    assert isinstance(_resolve_pr_provider(s), BitbucketPrProvider)


def test_resolves_azure_devops():
    s = SimpleNamespace(scm_type="azure_devops")
    assert isinstance(_resolve_pr_provider(s), AzureDevOpsPrProvider)


def test_returns_none_for_unknown_scm():
    s = SimpleNamespace(scm_type="unknown_scm")
    assert _resolve_pr_provider(s) is None
