# Architecture

This document describes the system architecture of Aegis for contributors who want to understand how everything fits together.

## Overview

Aegis is a monorepo with three main runtime components:

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Frontend   │◄──►│   Backend    │◄──►│   Runner     │
│   (Next.js)  │    │   (FastAPI)  │    │   (Python)   │
└──────────────┘    └──────┬───────┘    └──────┬───────┘
                           │                   │
                    ┌──────┴───────┐    ┌──────┴───────┐
                    │  PostgreSQL  │    │    MinIO     │
                    │              │    │  (artifacts) │
                    └──────────────┘    └──────────────┘
```

- **Frontend** — Next.js app router with React. Serves the UI and proxies API requests to the backend.
- **Backend** — FastAPI (async Python). REST + GraphQL APIs, business logic, database access, scan orchestration.
- **Runner** — Standalone Python process. Picks up scan jobs from the backend, runs all scanner modules in-process, uploads results to MinIO.

## Backend / Runner boundary

The backend and runner have strict, non-overlapping responsibilities.

- **Runner executes scanner tools.** All subprocess and library invocations of scanners (`grype`, `syft`, `semgrep`, `trufflehog`, `checkov`, and the in-process agent scanner) live in `runner/`. The backend never spawns a scanner process.
- **Runner parses tool output into the canonical Finding schema.** Tool-specific JSON shapes never leave the runner. The runner uploads only normalised findings to MinIO.
- **Backend stores normalised findings and exposes query/triage APIs.** Its job is read-and-serve over data the runner produced.
- **Backend never knows about tool-specific output shapes.** No fields named `semgrep_rule_id`, `grype_match`, `syft_artifact`, etc., in backend models or transforms.
- **Backend never executes scanner tools.** Enforced by `backend/src/tests/test_no_scanner_execution.py`; violations fail CI.

This boundary lets the runner be replaced or sharded without touching backend code, and lets the backend be queried, replicated, or migrated without re-running scans.

## Backend

### Module Structure

```
backend/src/
├── auth/               Authentication, sessions, SSO (SAML/OIDC), SCIM, MFA
├── authz/              Permission catalog, declarative enforcement, scope resolution
├── findings/           Unified findings API, lifecycle, decisions, assignments
├── scans/              Scan orchestration, job dispatch, BYO ingest
├── dependencies/       SCA ingest, lifecycle, OSV matching
├── code_scanning/      SAST ingest, lifecycle
├── containers/         Container image ingest, lifecycle, layer attribution
├── secrets/            Secret detection ingest, lifecycle
├── iac/                IaC ingest, lifecycle
├── agent_scanning/     Agent-threat ingest, lifecycle
├── osv/                OSV advisory mirror — nightly refresh, CVE matching
├── epss/               EPSS score ingestion and enrichment
├── kev/                CISA KEV catalog ingestion and enrichment
├── posture/            Posture scoring, trend resolvers
├── sla/                SLA config, violation detection, breach tracking
├── compliance/         Framework control mapping (SOC 2, ISO 27001, PCI DSS)
├── sbom/               SBOM export (CycloneDX/SPDX), browser, diff
├── reports/            Report template generation
├── rules/              Policy rule engine (SLA, scanner coverage, data retention)
├── notifications/      Event-driven notifications, routing, delivery history
├── history/            Event feed and release notes
├── search/             Global search across findings, repos, audit events
├── runner/             Runner registration, heartbeat, job queue
├── settings/           Configuration, auth-security, SSO, SCIM, LLM, integrations
│   ├── llm/            BYO LLM credential storage and routing
│   ├── sso/            SSO configuration
│   ├── notifications/  Notification destination management
│   └── integrations/   Integration catalog
├── connectors/         Connector wizards and SCM webhook receivers
├── graphql/            Strawberry GraphQL schema (framework primitives only)
├── shared/             Cross-cutting: config, encryption, rate limiting
└── db/                 SQLAlchemy models, Alembic migrations
```

Modules communicate through the database and shared utilities. There is no direct import between scanner modules.

### API Layer

The backend exposes two API styles, both under `/api/v1/`:

**REST** (`/api/v1/<resource>/*`) — used for state-changing operations and single-resource reads:
- Scan initiation, finding dismiss/reopen, run history
- Settings management, source connections, runner registration
- SBOM export/download, report generation
- Auth flows — login, logout, CSRF, session cookies
- Swagger docs at `/docs` (gated on `ENABLE_BACKEND_DOCS=true`)

**GraphQL** (`/api/v1/graphql`) — used by dashboards for joined, multi-resource queries:
- Finding counts and analytics across all scanners
- Posture trends, compliance summaries, SLA posture
- Filter options, user-controlled column selection
- GraphiQL at the same path (gated on `ENABLE_BACKEND_DOCS=true`)
- Security: depth limit 7, alias limit 10, introspection blocked in production

### Authentication and Authorization

Authentication uses session cookies (CSRF-protected). SSO via SAML and OIDC with JIT provisioning.

Authorization has two distinct gates on every endpoint:

**Permission gate** — enforced declaratively via `Depends(Permission(X))` on the route signature:
```python
@router.post("/manual")
async def manual_upload(
    _: None = Depends(Permission(MANAGE_SOURCES)),
) -> ...:
```
Permission constants live in `src/authz/permissions/catalog.py`. Raw string literals at call sites are rejected by CI.

**Scope gate** — BOLA prevention; enforced at the SQL layer via `resolve_asset_ids_from_request`:
```python
asset_ids = await resolve_asset_ids_from_request(request)
# then: .where(Finding.asset_id.in_(asset_ids))
```
Scope is never derived from request body or query string.

Failure responses: permission missing → 403; object out of scope → 404 (to prevent enumeration); list with empty scope → empty result set.

### Database

- PostgreSQL 16 with SQLAlchemy (async)
- Alembic for migrations — forward-only; `downgrade()` raises `NotImplementedError`
- Key tables: users, roles, findings, scan_runs, assets, sources, app_config, audit_events, llm_config, sla_config, compliance_controls

### Object Storage

MinIO (S3-compatible) for scan artifacts and SBOMs. Runner uploads under job-type prefixes; ingest reads the same prefix.

| Bucket | Prefix | Contents |
|---|---|---|
| `scans` | `dependencies_scanning/` | Dependency scan SBOM + findings |
| `scans` | `code_scanning/` | SAST findings |
| `scans` | `secret_scanning/` | Secret findings |
| `scans` | `container_scanning/` | Container scan SBOM + findings |
| `scans` | `iac_scanning/` | IaC findings |
| `scans` | `agent_scanning/` | Agent-threat findings |
| `sboms` | (bare name) | Exported SBOMs (CycloneDX/SPDX) |

### Encryption

`src/security/crypto.py` — Fernet encryption for sensitive data at rest. Source connection auth tokens, TOTP secrets, and LLM API keys are encrypted in the database, keyed from `APP_SECRET`.

## Frontend

### Routing

The frontend uses Next.js 15 app router:

```
frontend/app/
├── (app)/              Authenticated layout (sidebar + AppShell)
│   ├── overview/       Home dashboard — posture gauge, attack chains, recent activity
│   ├── findings/       Unified findings view across all scanners
│   ├── sources/        Source management — Git repos, container registries
│   ├── inventory/      Asset inventory
│   ├── posture/        Posture scoring — Overview and Triage tabs
│   ├── compliance/     Compliance framework mapping
│   ├── sbom/           SBOM browser and diff view
│   ├── history/        Event feed and releases
│   ├── settings/       Settings — auth, SSO, LLM, integrations, notifications
│   └── workspace/      Users, roles, teams, grants
├── api/                Next.js API routes (BFF proxy to backend)
└── login/              Unauthenticated login page
```

### BFF Proxy

The Next.js API routes act as a Backend-For-Frontend proxy. All backend traffic flows through `/api/*` → `/api/v1/*`, keeping the backend URL and session cookie handling internal.

### Real-Time Updates (SSE)

- Backend publishes events at `/api/v1/events/stream`
- Events: `scan.progress`, `scan.completed`, `scan.failed`, `source.synced`, `runner.status`, `notification.new`
- `BroadcastChannel` for leader election across browser tabs (one SSE connection per browser)
- Automatic fallback to polling after consecutive SSE failures

## Runner

The runner is a standalone Python process that:

1. Registers with the backend using `RUNNER_REGISTRATION_TOKEN`
2. Long-polls for scan jobs from the backend job queue (`/api/v1/agent/jobs/next`)
3. Executes the matching scanner module in-process (no Docker launch per scan)
4. Uploads result files to MinIO under the canonical job-type prefix
5. Reports progress and completion back to the backend
6. Sends periodic heartbeat with scanner status

### Scanner Modules

All scanners live in `runner/scanners/`:

| Module | Tools | Notes |
|---|---|---|
| `dependencies/` | Syft + Grype | Generates SBOM, matches against OSV mirror |
| `container/` | Syft + Grype | Container image scanning, layer attribution |
| `code_scanning/` | Semgrep + tree-sitter | SAST; LLM verification chains (optional) |
| `secrets/` | TruffleHog | Git history and filesystem modes |
| `iac/` | Checkov | IaC misconfiguration; LLM verification chains (optional) |
| `agent/` | Pure Python | In-process AI-agent-threat detection; no external binary |
| `_shared.py` | — | Shared LLM client builder, scan budget utilities |

Scanner modules read job parameters from `JobEnv` (the encrypted `envVars` payload the backend attaches to each job) rather than from the process environment.

### Security

- Git clone restricted to HTTPS only
- Commit hashes validated (hex 7–64 chars)
- File paths validated against directory traversal
- SSRF validation on container registry hosts
- MinIO access scoped to `scans/*` and `sboms/*`

## Scan Lifecycle

```
1. User initiates scan (UI or CLI)
       │
2. Backend creates scan_run record (status: queued)
   and dispatches one job per scanner type
       │
3. Runner polls, picks up the job
       │
4. Runner executes the scanner module in-process
   ┌──────────────────────────────────────────┐
   │  Scanner module:                          │
   │  1. Clone repo / pull image               │
   │  2. Run scanning tool or in-process logic │
   │  3. Normalise output to canonical schema  │
   │  4. (Optional) LLM verification pass      │
   │  5. Write result files                    │
   └──────────────────────────────────────────┘
       │
5. Runner uploads results to MinIO
       │
6. Backend ingests findings, applies lifecycle
   (new findings → open, missing findings → fixed)
       │
7. Notifications emitted for critical findings
```

## Notifications

Event-driven notification system with per-destination routing rules:
- Channels: Slack (beta), generic webhook (beta)
- Routing rules match on event type, severity, and scanner
- Delivery history tracked per notification
- Additional channels (Teams, PagerDuty, email digest) are in the connector catalog but not yet wired for delivery

## Source Management

Sources are external connections (Git repositories, container registries):
- Source connections store encrypted auth tokens
- Auto-sync discovers repositories and images from connected sources
- Team-based scoping: teams own assets; users see findings based on team membership
- Asset identity: canonical `external_ref` ties findings to their source asset
