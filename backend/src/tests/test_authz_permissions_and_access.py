"""Unit coverage for the role-permission expansion and team-access predicates.

`resolve_role_permissions` is the implied-grant expander (e.g. manage_settings
silently confers manage_runners for backwards compat) and `has_role_permission`
the role-string entry point both used off the request path. The `teams/access`
predicates decide object-level review/management access. All are security-
relevant and were previously only exercised indirectly through router tests.
"""
from __future__ import annotations

import pytest

from src.authz.permissions.service import (
    has_role_permission,
    resolve_role_permissions,
)
from src.authz.teams import access


# ── resolve_role_permissions ────────────────────────────────────────────────

def test_resolve_returns_explicit_permissions():
    out = resolve_role_permissions({"permissions": ["view_findings", "view_sources"]})
    assert out == {"view_findings", "view_sources"}


def test_resolve_empty_or_missing_permissions():
    assert resolve_role_permissions({}) == set()
    assert resolve_role_permissions({"permissions": []}) == set()


def test_resolve_expands_manage_settings_to_runners_and_view():
    # manage_settings must confer view_settings + manage_runners (backwards-compat
    # implication) so pre-split roles keep their runner-admin reach.
    out = resolve_role_permissions({"permissions": ["manage_settings"]})
    assert "manage_settings" in out
    assert "view_settings" in out
    assert "manage_runners" in out


@pytest.mark.parametrize(
    "parent,child",
    [
        ("manage_users", "view_users"),
        ("manage_roles", "view_roles"),
        ("manage_access_scope", "view_access_scope"),
        ("manage_sources", "view_sources"),
        ("export_findings", "view_findings"),
        ("export_reports", "view_reports"),
    ],
)
def test_resolve_each_manage_implies_its_view(parent, child):
    out = resolve_role_permissions({"permissions": [parent]})
    assert child in out


def test_resolve_does_not_invent_unrelated_permissions():
    # A view-only role gains nothing it wasn't granted.
    out = resolve_role_permissions({"permissions": ["view_users"]})
    assert out == {"view_users"}
    assert "manage_users" not in out


def test_resolve_implications_do_not_cascade_beyond_one_level():
    # export_findings → view_findings, and that's the end — no chain reaction.
    out = resolve_role_permissions({"permissions": ["export_findings"]})
    assert out == {"export_findings", "view_findings"}


# ── has_role_permission ─────────────────────────────────────────────────────

def test_has_role_permission_none_role_and_id_returns_false():
    assert has_role_permission(None, None, "view_findings") is False


def test_has_role_permission_resolves_by_role_id(monkeypatch):
    monkeypatch.setattr(
        "src.authz.roles.service.get_role",
        lambda rid: {"permissions": ["manage_settings"]},
    )
    # Implied permission resolves through the expander.
    assert has_role_permission(None, "role-123", "manage_runners") is True
    assert has_role_permission(None, "role-123", "manage_users") is False


def test_has_role_permission_resolves_by_role_slug(monkeypatch):
    monkeypatch.setattr(
        "src.authz.roles.service.get_role_by_slug",
        lambda slug: {"permissions": ["view_findings"]},
    )
    assert has_role_permission("viewer", None, "view_findings") is True
    assert has_role_permission("viewer", None, "manage_sources") is False


def test_has_role_permission_unknown_role_returns_false(monkeypatch):
    def _boom(_slug):
        raise ValueError("no such role")

    monkeypatch.setattr("src.authz.roles.service.get_role_by_slug", _boom)
    # A lookup miss is a deny, never a raise.
    assert has_role_permission("ghost", None, "view_findings") is False


def test_has_role_permission_prefers_role_id_over_slug(monkeypatch):
    monkeypatch.setattr(
        "src.authz.roles.service.get_role",
        lambda rid: {"permissions": ["manage_users"]},
    )

    def _slug_should_not_run(_slug):
        raise AssertionError("slug path must not be taken when role_id is set")

    monkeypatch.setattr("src.authz.roles.service.get_role_by_slug", _slug_should_not_run)
    assert has_role_permission("ignored-slug", "role-1", "view_users") is True


# ── teams/access predicates ─────────────────────────────────────────────────

def test_can_review_repository_short_circuits_on_manage_access_scope(monkeypatch):
    # MANAGE_ACCESS_SCOPE grants review regardless of membership.
    monkeypatch.setattr(
        "src.authz.permissions.service.has_role_permission",
        lambda role, role_id, perm: perm == "manage_access_scope",
    )
    assert access.can_review_repository("admin", is_member=False) is True


def test_can_review_repository_non_member_without_scope_denied(monkeypatch):
    monkeypatch.setattr(
        "src.authz.permissions.service.has_role_permission",
        lambda role, role_id, perm: False,
    )
    assert access.can_review_repository("viewer", is_member=False) is False


def test_can_review_repository_member_needs_review_findings(monkeypatch):
    granted = {"review_findings"}
    monkeypatch.setattr(
        "src.authz.permissions.service.has_role_permission",
        lambda role, role_id, perm: perm in granted,
    )
    assert access.can_review_repository("member", is_member=True) is True


def test_can_manage_team_delegates_to_manage_organisations(monkeypatch):
    monkeypatch.setattr(
        "src.authz.permissions.service.has_role_permission",
        lambda role, role_id, perm: perm == "manage_organisations",
    )
    assert access.can_manage_team("admin") is True
    monkeypatch.setattr(
        "src.authz.permissions.service.has_role_permission",
        lambda role, role_id, perm: False,
    )
    assert access.can_manage_team("viewer") is False


def test_user_has_asset_access_matches_direct_grant():
    grants = [{"userId": "u1", "assetId": "a1"}, {"userId": "u2", "assetId": "a2"}]
    assert access.user_has_asset_access([], "u1", "a1", grants) is True
    # Right user, wrong asset → no access (BOLA guard).
    assert access.user_has_asset_access([], "u1", "a2", grants) is False
    # Right asset, wrong user → no access.
    assert access.user_has_asset_access([], "u3", "a1", grants) is False


def test_user_has_asset_access_no_grants_is_false():
    assert access.user_has_asset_access([], "u1", "a1", None) is False
    assert access.user_has_asset_access([], "u1", "a1", []) is False


def test_user_has_any_scoped_access_true_only_with_a_user_grant():
    grants = [{"userId": "u1", "assetId": "a1"}]
    assert access.user_has_any_scoped_access([], "u1", grants) is True
    assert access.user_has_any_scoped_access([], "u9", grants) is False
    assert access.user_has_any_scoped_access([], "u1", None) is False


def test_repository_and_image_helpers_are_fail_closed_stubs():
    # These remain hard False pending the asset_id migration; pin that so a
    # premature "return True" can't slip in unnoticed.
    assert access.user_has_repository_access([], "u1", "org", "repo") is False
    assert access.user_has_container_image_access([], "u1", "img") is False


def test_effective_team_role_is_none_legacy_stub():
    assert access.get_effective_team_role_for_repository([], "u1", "org", "repo") is None
