# `src.authz` — bounded-context layout

Every authorization surface lives under this tree, split into four
sub-packages by bounded context. The split exists to separate the
*decision* logic (pure functions over roles + permissions) from the
*enforcement* logic (request-time wrappers that raise 403), and to keep
the role / team data accessors in clearly-owned modules.

`auth/` answers "who is this caller?". `authz/` answers "is this caller
allowed to do this?". Each tree is independent of the other at the
package boundary — see "Dependency direction" below.

## Layout

```
src/authz/
├── roles/           role records, the catalog of role kinds, and the
│                    `/api/v1/settings/roles` CRUD router
├── teams/           team membership, team-asset attachments, and the
│                    team-scoped access predicates
├── permissions/     the pure permission decision point (PDP)
└── enforcement/     the request-time policy enforcement point (PEP)
                    and the asset-scope resolver
```

### `roles/`
Role CRUD and the protected-role guards.

- `service.py` — Role DB access (`list_roles`, `get_role`,
  `get_role_by_slug`, `create_role`, `update_role`, `delete_role`,
  `role_kind_from_id`) plus the built-in permission catalog
  (`BUILTIN_PERMISSION_IDS`).
- `router.py` — `/api/v1/settings/roles` REST endpoints. URL is
  preserved; only the code location moves.

### `teams/`
Team membership and team-asset attachments.

- `service.py` — Team CRUD, member upsert/remove, repository / container
  image attach/detach, GitHub-sync preview application. Exposes
  `OrganisationValidationError`, `OrganisationNotFoundError`, and
  `OrganisationStoreError` to callers.
- `access.py` — Team-asset access predicates consumed by routers and
  resolvers: `actor_user_id`, `actor_global_role`, `can_manage_team`,
  `can_review_repository`, `user_has_asset_access`, and friends.

### `permissions/`
The Policy Decision Point (PDP). Pure functions: given a role record (or
role ID / slug) and a permission name, return a bool. **No `Request`
parameter.** Safe to call from non-route code (store helpers, async
workers, GraphQL resolvers).

- `service.py` — `resolve_role_permissions(role_record)` expands a
  role's declared permissions to its full effective set (including
  implied permissions). `has_role_permission(role, role_id, permission)`
  wraps the lookup-then-check pattern for callers that have a role
  string or ID but not a request.

`catalog.py` is **reserved for Stream B** of v0.4.6 — do not add it
here. Until then, the canonical permission list lives at
`roles.service.BUILTIN_PERMISSION_IDS`.

### `enforcement/`
The Policy Enforcement Point (PEP). Request-time wrappers consumed by
FastAPI routers.

- `__init__.py` — `require_permission(request, perm)` raises
  `HTTPException(403)` when the caller lacks `perm`;
  `has_permission(request, perm)` returns a bool.
- `dependencies.py` — `Permission(perm)` is a FastAPI dependency class
  that runs the same check declaratively, via
  `Depends(Permission(perm))` in the route signature.
- `scope.py` — asset-visibility resolver. `get_user_asset_ids` is the
  single auth boundary that decides which assets a request may read;
  `apply_scope` embeds the resolved IDs into a SQLAlchemy `Select`;
  `resolve_asset_ids_from_request` is the standard router-side helper.

## Imperative vs declarative enforcement

Both patterns share the same PDP (`has_role_permission`) and the same
403 response on deny. Pick based on the call site:

### `require_permission(request, PERM)` — imperative

Use when the check is **conditional** or **data-dependent**:

- The permission to check is computed at runtime from parsed body /
  path params (e.g. dispatch on `rule.category`):

  ```python
  @router.post("/rules")
  async def create_rule(request: Request, body: RuleRequest) -> dict:
      perm = MANAGE_PERMISSION_BY_RULE_CATEGORY[body.category]
      require_permission(request, perm)
      ...
  ```

- The check only runs on some branches (one route serves multiple
  behaviours, only the privileged branch needs the guard):

  ```python
  if body.includeSecrets:
      require_permission(request, MANAGE_SETTINGS)
  ```

### `Depends(Permission(PERM))` — declarative

Use when the check is **unconditional** for the whole route. The route
signature shows the auth requirement, the generated OpenAPI schema
surfaces it, and tests can override the dependency without monkey-
patching internals:

```python
from src.authz.enforcement.dependencies import Permission

@router.get("/keys")
async def list_api_keys(_: None = Depends(Permission(MANAGE_SETTINGS))) -> dict:
    ...
```

Compose with other dependencies as usual:

```python
@router.get("/download")
def download_sbom(
    request: Request,
    orgs: list[str] = Depends(require_orgs),
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> Response:
    ...
```

Multiple permissions are AND semantics — every listed permission must
be present, otherwise 403:

```python
Depends(Permission(MANAGE_SETTINGS, RUN_SCANS))
```

If you need OR semantics, split into separate routes or hand-roll a
small guard at the call site — `Permission(...)` deliberately does not
support OR.

### Test ergonomics

`Permission` instances built from the same permission tuple compare
equal and hash to the same bucket, so

```python
app.dependency_overrides[Permission(MANAGE_SETTINGS)] = lambda: None
```

bypasses the check regardless of which `Permission(MANAGE_SETTINGS)`
instance the route declared. `app.dependency_overrides` is **global
mutable state on the app**, so fixture finalizers must clear the entry
or later tests will run with the override still in place:

```python
@pytest.fixture
def bypass_manage_settings(app):
    key = Permission(MANAGE_SETTINGS)
    app.dependency_overrides[key] = lambda: None
    try:
        yield
    finally:
        app.dependency_overrides.pop(key, None)
```

For `require_permission`-style routes, the established test pattern is
to patch `src.authz.enforcement._resolve_effective_permissions` (see
existing router tests). That pattern continues to work — both
enforcement styles share the underlying role-to-permission expansion.

## PDP vs PEP

The split between `permissions/` and `enforcement/` is deliberate:

- **PDP (decision)** is a pure function. Takes a role and a permission,
  returns a bool. Safe to call from anywhere — store helpers, GraphQL
  resolvers, background jobs.
- **PEP (enforcement)** is request-time. Takes a FastAPI `Request`,
  resolves the caller's effective permissions, and raises 403 if
  missing. Only routers and request-scoped helpers should import from
  `enforcement/`.

Keeping the two on different sides of the boundary prevents
non-request code from accidentally pulling in `HTTPException` (and the
implicit assumption that we are inside an HTTP handler) when it just
needs to check whether a role has a permission.

## Dependency direction

The dependency graph between auth-related packages is one-way. Future
PRs must respect this:

```
authz/ ──→ auth/, db/, shared/        ✓ allowed
auth/  ──→ authz/                     ✗ forbidden
db/    ──→ authz/                     ✗ forbidden
```

- `authz/` may import from `auth/` (e.g. the `User` model in
  `db/models.py`, identity helpers in `auth/identity/`), from `db/`
  (models, engine, helpers), and from `shared/` (general utilities).
- `auth/` must never import from `authz/`. Authentication (who is the
  caller?) precedes authorization (what may the caller do?), so the
  authz layer is downstream of auth, not the other way around.
- `db/models.py` must never import from `authz/`. The data model
  defines the storage shape; the access logic on top of it lives in
  `authz/`.

## URL stability

URLs are deliberately untouched by this layout:

- `/api/v1/settings/roles/*` continues to be served by `roles.router`.
- `/api/v1/settings/organisations/*` (which today fronts team CRUD) is
  still mounted by `settings/organisations_router.py`. The underlying
  team service moved to `authz/teams/service.py`, but the URL prefix
  stayed put. Any consolidation of the URL surface is out of scope for
  v0.4.6 and would be a follow-up decision.

## Data models stay in `db/`

`Role`, `Team`, `TeamMember`, `TeamAsset`, and `DirectGrant` continue to
live in `db/models.py`. Only the access code moved.
