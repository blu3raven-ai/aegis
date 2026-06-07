import pytest

from src.shared.providers.base import (
    ImageRegistry,
    RepoProvider,
    UnknownProvider,
    get_image_registry,
    get_repo_provider,
    register_image_registry,
    register_repo_provider,
)


def test_get_repo_provider_returns_registered_instance():
    class FakeRepoProvider:
        source_type = "fake-scm"
        def clone_url(self, org: str, repo: str, instance_url: str) -> str:
            return f"fake://{org}/{repo}"

    p = FakeRepoProvider()
    register_repo_provider(p)
    assert get_repo_provider("fake-scm") is p


def test_get_image_registry_returns_registered_instance():
    class FakeRegistry:
        source_type = "fake-registry"
        def normalize_image_ref(self, org: str, name: str, instance_url: str) -> str:
            return f"fake/{org}/{name}"

    r = FakeRegistry()
    register_image_registry(r)
    assert get_image_registry("fake-registry") is r


def test_get_repo_provider_raises_for_unknown_source_type():
    with pytest.raises(UnknownProvider, match="not-a-real-provider"):
        get_repo_provider("not-a-real-provider")


def test_get_image_registry_raises_for_unknown_source_type():
    with pytest.raises(UnknownProvider, match="not-a-real-registry"):
        get_image_registry("not-a-real-registry")
