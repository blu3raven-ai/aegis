"""Input-validation coverage for authz/teams/service.py normalizers — the trust
boundary that parses user-supplied team names, repo refs, and image refs."""
from __future__ import annotations

import pytest

from src.authz.teams.service import (
    OrganisationValidationError,
    _team_name_key,
    normalize_container_image,
    normalize_repository,
    normalize_team_name,
)


def test_team_name_trimmed_and_required():
    assert normalize_team_name("  Platform  ") == "Platform"
    with pytest.raises(OrganisationValidationError, match="required"):
        normalize_team_name("   ")


def test_team_name_key_is_case_and_space_insensitive():
    assert _team_name_key("  Platform ") == "platform"


def test_repository_must_be_org_slash_repo():
    assert normalize_repository("acme-org/example-repo") == {"org": "acme-org", "repo": "example-repo"}


@pytest.mark.parametrize("bad", ["norepo", "too/many/parts", "/repo", "org/", "org repo"])
def test_repository_rejects_bad_shapes(bad):
    with pytest.raises(OrganisationValidationError, match="org/repo"):
        normalize_repository(bad)


def test_container_image_must_be_ghcr():
    assert normalize_container_image("ghcr.io/acme-org/example") == {"image": "ghcr.io/acme-org/example"}


@pytest.mark.parametrize("bad", [
    "docker.io/acme/example",   # wrong registry
    "ghcr.io/acme",             # too few parts
    "acme/example/image",       # not ghcr.io
    "ghcr.io//image",           # empty part
])
def test_container_image_rejects_non_ghcr(bad):
    with pytest.raises(OrganisationValidationError, match="ghcr.io"):
        normalize_container_image(bad)
