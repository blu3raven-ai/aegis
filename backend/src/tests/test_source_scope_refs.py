"""_scope_refs maps a connection's raw discovered items to the canonical asset
refs (display_name format) the findings list scopes by."""
from types import SimpleNamespace

from src.sources.store import _scope_refs


def _conn(source_type, items):
    return SimpleNamespace(source_type=source_type, discovered_items=items)


def test_repo_items_become_canonical_repo_refs():
    refs = _scope_refs(
        _conn("github", ["acme-org/example-repo", "acme-org/example-worker"])
    )
    assert refs == [
        "github:acme-org/example-repo",
        "github:acme-org/example-worker",
    ]


def test_source_type_is_normalised_like_repo_ref():
    assert _scope_refs(_conn("GitHub", ["acme/foo"])) == ["github:acme/foo"]


def test_display_cased_owner_maps_to_lowercased_ref():
    # Discovered items keep the provider's display casing ("Acme-Org/...")
    # but assets are stored lower-cased, so the scope ref must lower-case the
    # owner (name case preserved) or the per-source findings list comes up empty.
    assert _scope_refs(_conn("github", ["Acme-Org/MyRepo"])) == ["github:acme-org/MyRepo"]


def test_registry_image_items_become_image_refs():
    assert _scope_refs(_conn("dockerhub", ["dockerhub/nginx:1.27"])) == [
        "dockerhub:nginx:1.27"
    ]


def test_unconvertible_and_empty_items_are_skipped():
    assert _scope_refs(_conn("github", [])) == []
    assert _scope_refs(_conn("github", ["noslash", "", None])) == []


def test_unknown_source_type_skips_repo_items_rather_than_raising():
    # repo_ref raises on an unknown source_type; _scope_refs must swallow it.
    assert _scope_refs(_conn("mystery", ["acme/foo"])) == []
