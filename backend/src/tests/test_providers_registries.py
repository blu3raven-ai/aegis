import pytest

from src.shared.providers.registries import (
    AcrRegistry,
    DockerHubRegistry,
    EcrRegistry,
    GcrRegistry,
    GhcrRegistry,
    GitLabContainerRegistry,
)


@pytest.mark.parametrize(
    "registry_cls, org, name, instance_url, expected",
    [
        # GHCR: always prefix with ghcr.io/{org}/
        (GhcrRegistry, "acme", "img", "", "ghcr.io/acme/img"),
        (GhcrRegistry, "acme", "img:v1", "", "ghcr.io/acme/img:v1"),

        # Docker Hub: prefix with {org}/ only when no slash in name
        (DockerHubRegistry, "acme", "img", "", "acme/img"),
        (DockerHubRegistry, "acme", "img:v1", "", "acme/img:v1"),
        (DockerHubRegistry, "acme", "library/nginx", "", "library/nginx"),

        # ECR: prefix with instance_url if set, else passthrough
        (EcrRegistry, "acme", "img:v1", "", "img:v1"),
        (EcrRegistry, "acme", "img:v1", "123456789.dkr.ecr.us-east-1.amazonaws.com",
         "123456789.dkr.ecr.us-east-1.amazonaws.com/img:v1"),

        # ACR: same shape as ECR
        (AcrRegistry, "acme", "img", "", "img"),
        (AcrRegistry, "acme", "img:v1", "myacr.azurecr.io",
         "myacr.azurecr.io/img:v1"),

        # GCR: defaults to gcr.io if no instance_url; always includes {org}
        (GcrRegistry, "acme", "img:v1", "", "gcr.io/acme/img:v1"),
        (GcrRegistry, "acme", "img:v1", "us.gcr.io", "us.gcr.io/acme/img:v1"),

        # GitLab container registry: defaults to registry.gitlab.com
        (GitLabContainerRegistry, "acme", "img:v1", "",
         "registry.gitlab.com/acme/img:v1"),
        (GitLabContainerRegistry, "acme", "img:v1",
         "registry.git.acme.io", "registry.git.acme.io/acme/img:v1"),
    ],
)
def test_registry_normalize(registry_cls, org, name, instance_url, expected):
    assert registry_cls().normalize_image_ref(org, name, instance_url) == expected


@pytest.mark.parametrize(
    "registry_cls, expected_source_type",
    [
        (GhcrRegistry, "ghcr"),
        (DockerHubRegistry, "docker-hub"),
        (EcrRegistry, "ecr"),
        (AcrRegistry, "acr"),
        (GcrRegistry, "gcr"),
        (GitLabContainerRegistry, "gitlab-registry"),
    ],
)
def test_registry_source_type(registry_cls, expected_source_type):
    assert registry_cls().source_type == expected_source_type
