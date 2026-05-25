import pytest
from src.graphql.auth import get_graphql_context, GraphQLAuthError


def test_auth_context_rejects_missing_user():
    class FakeRequest:
        state = type("S", (), {"user_sub": None, "user_role": None})()

    with pytest.raises(GraphQLAuthError, match="Unauthorized"):
        get_graphql_context(FakeRequest())


def test_auth_context_extracts_user(monkeypatch):
    # Patch dependencies to avoid real config/DB reads
    monkeypatch.setattr("src.graphql.auth.get_orgs_from_source_connections", lambda: ["org-a"])
    monkeypatch.setattr("src.settings.router.has_permission", lambda req, perm: True)

    class FakeState:
        user_sub = "user-1"
        user_role = "admin"
        user_role_id = "role-1"
        tier = "pro"
        license_claims = {}

    class FakeRequest:
        state = FakeState()

    ctx = get_graphql_context(FakeRequest())
    assert ctx["user_id"] == "user-1"
    assert ctx["role"] == "admin"


def test_org_scope_validation():
    from src.graphql.auth import validate_org_access

    ctx = {"user_id": "u1", "role": "viewer", "orgs": ["org-a", "org-b"]}
    validate_org_access(ctx, "org-a")  # should not raise

    with pytest.raises(GraphQLAuthError, match="Access denied"):
        validate_org_access(ctx, "org-c")


def test_load_scoped_findings_multi_org(monkeypatch):
    """_load_scoped_findings must accept a comma-joined org string and merge findings."""
    from src.graphql import dependencies_resolvers

    findings_by_org = {
        "org-a": [{"id": "1", "org": "org-a"}],
        "org-b": [{"id": "2", "org": "org-b"}],
    }
    monkeypatch.setattr(
        dependencies_resolvers, "read_dependencies_findings",
        lambda org: findings_by_org.get(org, []),
    )

    ctx = {"user_id": "u1", "role": "viewer", "orgs": ["org-a", "org-b"], "_cache": {}}
    result = dependencies_resolvers._load_scoped_findings("org-a,org-b", ctx)
    assert len(result) == 2
    assert {f["id"] for f in result} == {"1", "2"}


def test_load_scoped_findings_multi_org_access_denied():
    """_load_scoped_findings must reject if any org in a comma-joined string is not allowed."""
    from src.graphql.auth import GraphQLAuthError
    from src.graphql import dependencies_resolvers

    ctx = {"user_id": "u1", "role": "viewer", "orgs": ["org-a"], "_cache": {}}
    with pytest.raises(GraphQLAuthError, match="Access denied"):
        dependencies_resolvers._load_scoped_findings("org-a,org-b", ctx)


def test_query_depth_within_limit():
    from src.graphql.limits import check_query_depth
    query = '{ scaCounts(org: "a") { total critical } }'
    check_query_depth(query, max_depth=5)  # should not raise


def test_query_depth_exceeds_limit():
    from src.graphql.limits import check_query_depth
    deep = "{ a { b { c { d { e { f { g } } } } } } }"
    with pytest.raises(ValueError, match="depth"):
        check_query_depth(deep, max_depth=5)


def test_per_page_clamped():
    from src.graphql.limits import clamp_per_page
    assert clamp_per_page(None) == 25
    assert clamp_per_page(0) == 1
    assert clamp_per_page(-5) == 1
    assert clamp_per_page(50) == 50
    assert clamp_per_page(999) == 100


def test_alias_counting():
    """Verify alias counting in AliasLimitExtension."""
    from src.graphql.schema import AliasLimitExtension
    ext = AliasLimitExtension.__new__(AliasLimitExtension)

    from graphql import parse
    doc = parse('{ a: scaCounts(org: "x") { total } b: scaCounts(org: "y") { total } }')
    assert ext._count_aliases(doc) == 2

    doc_no_alias = parse('{ scaCounts(org: "x") { total } }')
    assert ext._count_aliases(doc_no_alias) == 0
