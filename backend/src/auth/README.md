# `src.auth` — bounded-context layout

Every auth surface lives under this tree, split into five sub-packages by
bounded context. The split exists so each module has a single clear owner
and so middleware / runtime hot paths are visually separated from
admin-time configuration.

## Layout

```
src/auth/
├── authentication/   who's logging in right now
├── federation/       how external IdPs authenticate users
├── identity/         who exists in the system (SCIM 2.0)
├── credentials/      non-session-based identity proofs (API keys)
└── policy/           admin-configurable knobs
```

### `authentication/`
The session lifecycle for first-party login: rate-limited login endpoints,
session issuance and validation, the cookie helpers, CSRF, CSP, security
headers, and the legacy-redirect + session-gate middlewares. Mounted by
the FastAPI middleware stack on every request.

### `federation/`
The external-IdP login flows — SAML SP routes (login / ACS / metadata),
OIDC routes (login / callback), JIT user provisioning, and the small
state-cookie helper they share. The `/api/v1/auth/sso/availability`
endpoint also lives here (public, surfaced by the login screen).

### `identity/`
The SCIM 2.0 surface (`/scim/v2/*`) used by external IdPs to provision
and deprovision users. Two layers:

- `auth.py` — bearer-token verifier consumed as a FastAPI dependency on
  every SCIM call. **Runtime hot path.**
- `router.py` + `schemas.py` — the SCIM Users / Groups endpoints
  themselves.

### `credentials/`
API-key surface. Two layers, similar to `identity/`:

- `middleware.py` + `auth.py` — token verification and `request.state`
  population. **Runtime hot path** (every `Bearer ak_*` request).
- `router.py` + `service.py` + `models.py` — admin CRUD for issuing and
  revoking keys. **Cold path.**

### `policy/`
The admin-configurable settings backing the above modules:

- `sso_settings_router.py` — `GET`/`PATCH /api/v1/settings/sso`, SAML
  SP key-pair generation, metadata refresh.
- `scim_settings_router.py` — `GET`/`PATCH /api/v1/settings/scim`, SCIM
  bearer-token issue / revoke.
- `auth_security_router.py` — `PATCH /api/v1/settings/auth-security` for
  the password / session / MFA policy knobs.

## URL stability

URLs are deliberately untouched by this layout. SCIM 2.0 mandates
`/scim/v2/*`; SAML and OIDC endpoint URLs are pasted into customer IdP
configurations and must not move. This module reorg is purely a
code-location change.
