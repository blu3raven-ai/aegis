# `src.settings` — bounded-context layout

Every admin-facing settings surface lives under this tree, split into
sub-packages by URL prefix. Each sub-package owns the router, the
service helpers, the schemas, and the GraphQL resolver for one
`/api/v1/settings/<x>` path.

`auth/` answers "who is this caller?". `authz/` answers "is this caller
allowed to do this?". `settings/` owns the org-wide configuration the
caller can read and write once they pass authn and authz.

## Layout

```
src/settings/
├── general/         /api/v1/settings (root) — org name, account, tools,
│                    advisory sources, GitHub rate-limit probe
├── audit_stream/    /api/v1/settings/audit/stream — outbound audit log
│                    streaming destinations
├── auth_security/   /api/v1/settings/auth-security — password policy,
│                    lockout, MFA enforcement
├── sso/             /api/v1/settings/sso — SAML / OIDC config
├── scim/            /api/v1/settings/scim — SCIM provisioning config
├── llm/             /api/v1/settings/llm and /llm/usage — provider
│                    config and usage accounting
├── notifications/   /api/v1/notifications (destinations, rules)
│                    + the signing-secret rotation router
├── saved_views/     /api/v1/settings/saved-views — per-table saved
│                    filter sets
├── webhooks/        /api/v1/settings/webhooks — outbound webhook
│                    destinations
└── organisations/   /api/v1/settings/organisation — org branding
                     (name, logo); team CRUD itself lives in
                     authz/teams/
```

### Per sub-package files

- `router.py` — the FastAPI router (REST surface)
- `service.py` — DB access + business logic (where applicable)
- `schemas.py` — Pydantic request/response models (where applicable)
- `resolvers.py` — Strawberry GraphQL resolver functions
  (added in the GraphQL consolidation PR)

## Dependency direction

```
settings/ ──→ auth/, authz/, db/, shared/, notifications/,
              license/, runner/                ✓ allowed
auth/     ──→ settings/                        ✗ forbidden
authz/    ──→ settings/                        ✗ forbidden
db/       ──→ settings/                        ✗ forbidden
```

- `auth/` (authentication) precedes `settings/`. Authentication does
  not read settings to decide identity.
- `authz/` is called BY settings routers via
  `require_permission(MANAGE_SETTINGS)`, not the reverse.
- `db/models.py` defines tables; `settings/` reads and writes via
  SQLAlchemy. Models never import settings.
- `settings/general/router.py` retains
  `from src.runner.registry import list_approved_online_runners` for
  scanner prerequisite checks. Runner is a peer bounded context, not
  upstream — peer→peer is allowed.

## URL stability

URLs are deliberately untouched by this layout. Every
`/api/v1/settings/<x>` path served before this refactor continues to be
served from the same path; only the file locations moved.

`/api/v1/notifications/destinations/{id}/signing-secret` (the
signing-secret rotation endpoint) is served from
`settings/notifications/signing_router.py`.

## Data models stay in `db/`

`OrgSettings`, `SsoConfig`, `ScimConfig`, `NotificationDestination`,
`NotificationRule`, `SavedView`, `WebhookEndpoint`, `LlmUsage`, and
`AuditStreamConfig` continue to live in `db/models.py`. Only the
access code lives here.
