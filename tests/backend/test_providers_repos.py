import pytest

from src.shared.providers.repos import (
    BitbucketRepoProvider,
    GiteaRepoProvider,
    GitHubRepoProvider,
    GitLabRepoProvider,
)


@pytest.mark.parametrize(
    "provider_cls, org, repo, instance_url, expected",
    [
        (GitHubRepoProvider, "acme", "foo", "", "https://github.com/acme/foo.git"),
        (GitHubRepoProvider, "acme", "foo", "https://ghe.acme.io",
         "https://ghe.acme.io/acme/foo.git"),
        (GitLabRepoProvider, "acme", "foo", "", "https://gitlab.com/acme/foo.git"),
        (GitLabRepoProvider, "acme", "foo", "https://git.acme.io",
         "https://git.acme.io/acme/foo.git"),
        (BitbucketRepoProvider, "acme", "foo", "", "https://bitbucket.org/acme/foo.git"),
        (BitbucketRepoProvider, "acme", "foo", "https://bb.acme.io",
         "https://bb.acme.io/acme/foo.git"),
        (GiteaRepoProvider, "acme", "foo", "", "https://gitea.com/acme/foo.git"),
        (GiteaRepoProvider, "acme", "foo", "https://gitea.acme.io",
         "https://gitea.acme.io/acme/foo.git"),
    ],
)
def test_repo_provider_builds_correct_clone_url(
    provider_cls, org, repo, instance_url, expected,
):
    p = provider_cls()
    assert p.clone_url(org, repo, instance_url) == expected


@pytest.mark.parametrize(
    "provider_cls, expected_source_type",
    [
        (GitHubRepoProvider, "github"),
        (GitLabRepoProvider, "gitlab"),
        (BitbucketRepoProvider, "bitbucket"),
        (GiteaRepoProvider, "gitea"),
    ],
)
def test_repo_provider_source_type(provider_cls, expected_source_type):
    assert provider_cls().source_type == expected_source_type
