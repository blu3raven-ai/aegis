import pytest

from src.assets.refs import image_ref, owner_from_external_ref, repo_ref


def test_owner_from_external_ref_repo():
    assert owner_from_external_ref("github:acme/foo") == "acme"


def test_owner_from_external_ref_image():
    assert owner_from_external_ref("ghcr:acme/img:v1") == "acme"


def test_owner_from_external_ref_rejects_no_colon():
    with pytest.raises(ValueError, match="unrecognized"):
        owner_from_external_ref("acme/foo")


def test_owner_from_external_ref_rejects_no_slash():
    with pytest.raises(ValueError, match="unrecognized"):
        owner_from_external_ref("github:acme")


def test_repo_ref_lowercases_source_type():
    assert repo_ref("GitHub", "acme", "foo") == "github:acme/foo"


def test_repo_ref_lowercases_owner_preserves_name_case():
    # Provider owners/orgs are case-insensitive and assets are stored with a
    # lower-cased owner, so the canonical ref lower-cases the owner. The repo
    # name keeps its case (repository names are case-sensitive).
    assert repo_ref("github", "Acme-Org", "MyRepo") == "github:acme-org/MyRepo"


def test_repo_ref_strips_owner_and_name_whitespace():
    assert repo_ref("github", "  acme ", " foo ") == "github:acme/foo"


def test_repo_ref_rejects_empty_owner():
    with pytest.raises(ValueError, match="owner"):
        repo_ref("github", "", "foo")


def test_repo_ref_rejects_empty_name():
    with pytest.raises(ValueError, match="name"):
        repo_ref("github", "acme", "")


def test_repo_ref_rejects_unknown_source_type():
    with pytest.raises(ValueError, match="source_type"):
        repo_ref("invalid", "acme", "foo")


def test_image_ref_lowercases_registry():
    assert image_ref("GHCR", "acme/img", "v1.2.3") == "ghcr:acme/img:v1.2.3"


def test_image_ref_defaults_tag_to_latest_when_missing():
    assert image_ref("ghcr", "acme/img", "") == "ghcr:acme/img:latest"


def test_image_ref_rejects_empty_image():
    with pytest.raises(ValueError, match="image"):
        image_ref("ghcr", "", "v1")


def test_image_ref_rejects_unknown_registry():
    with pytest.raises(ValueError, match="registry"):
        image_ref("unknown", "acme/img", "v1")


def test_image_ref_normalizes_docker_hub_alias():
    # source connections use "docker-hub"; image_ref canonicalises to "dockerhub"
    assert image_ref("docker-hub", "library/nginx", "1.27") == "dockerhub:library/nginx:1.27"


def test_image_ref_accepts_gitlab_registry():
    assert image_ref("gitlab-registry", "acme/img", "v1") == "gitlab-registry:acme/img:v1"


def test_repo_ref_accepts_gitea():
    assert repo_ref("gitea", "acme", "foo") == "gitea:acme/foo"
