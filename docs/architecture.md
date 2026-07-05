# Architecture

This document describes the system architecture of Aegis for contributors who want to understand how everything fits together.

## Overview

Aegis is a monorepo with four main components:

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Frontend   │◄──►│   Backend    │◄──►│   Runner     │
│   (Next.js)  │    │   (FastAPI)  │    │   (Python)   │
└──────────────┘    └──────┬───────┘    └──────┬───────┘
                           │                   │
                    ┌──────┴───────┐    ┌──────┴───────┐
                    │  PostgreSQL  │    │   Scanners   │
                    │  + MinIO     │    │   (Docker)   │
                    └──────────────┘    └──────────────┘
```

- **Frontend** — Next.js app router with React. Serves the UI and proxies API requests to the backend.
- **Backend** — FastAPI (async Python). REST + GraphQL APIs, business logic, database access.
- **Runner** — Standalone Python process. Builds scanner images, picks up scan jobs, executes them in Docker containers, uploads results.
- **Scanners** — Purpose-built Docker images, one per tool. Each contains the scanning tools and a shell script that orchestrates the scan.

## Backend / Runner boundary

The backend and runner have strict, non-overlapping responsibilities.

- **Runner executes scanner tools.** All subprocess, shell, and library invocations of scanners (`trivy`, `grype`, `syft`, `semgrep`, `joern`, `trufflehog`, `bandit`, `kics`, `checkov`, `osv-scanner`, and any future scanner) live in `runner/`. The backend never spawns a scanner process.
- **Runner parses tool output into the canonical Finding schema.** Tool-specific JSON shapes never leave the runner. The runner uploads only normalised findings.
- **Backend stores normalised findings and exposes query/triage APIs.** Its job is read-and-serve over data the runner produced.
- **Backend never knows about tool-specific output shapes.** No fields named `trivy_vulnerability`, `semgrep_rule_id`, `grype_match`, etc., in backend models, schemas, or transforms.
- **Backend never executes scanner tools.** Enforced by `backend/src/tests/test_no_scanner_execution.py`; future violations fail CI.

This boundary lets the runner be replaced, sandboxed, or sharded without touching backend code, and lets the backend be queried, replicated, or migrated without re-running scans.

## Backend

### Module Structure

Each scanning tool is an independent module under `backend/src/`:

```
backend/src/
├── dependencies/       # SCA — Syft + Grype
│   ├── router.py       # REST endpoints (/dependencies/api/*)
│   ├── scanner.py      # Scan orchestration
│   ├── store.py        # Finding storage and queries
│   └── sbom_store.py   # SBOM storage (MinIO)
├── code_scanning/      # SAST — Opengrep
├── containers/         # Container image scanning
├── secrets/            # Secret detection
├── shared/             # Cross-cutting utilities
├── graphql/            # Strawberry GraphQL schema
├── auth/               # Authentication and authorization
├── notifications/      # Event-driven notifications
├── settings/           # Configuration management
├── runner/             # Runner registration and job queue
└── db/                 # SQLAlchemy models and helpers
```

Modules communicate through shared utilities (`backend/src/shared/`) and the database. There is no direct import between tool modules.

### API Layer

The backend exposes two API styles:

**GraphQL** (`/graphql/api`) — Used by dashboards for:
- Finding counts and analytics per tool
- Filter options (severities, sources, statuses)
- Posture trends and home dashboard data
- 18 query fields, per-request cache, depth/alias limits

**REST** — Used for mutations and tool-specific endpoints:
- `/dependencies/api/*`, `/code-scanning/api/*`, `/secrets/api/*`, `/container-scanning/api/*`
- Scan initiation, finding dismiss/reopen, run history
- Settings management, source connections, runner registration

GraphQL security: introspection blocked in production, alias limit (10), depth limit (5), field suggestions disabled.

### Authentication and Authorization

- JWT-based authentication with `require_permission()` decorator
- Role-based access control with granular permissions (e.g., `view_findings`, `manage_settings`, `initiate_scans`)
- No owner bypass — all users go through the same permission checks
- `has_permission()` bool helper for conditional logic
- Internal verification endpoints: `/verify-password`, `/verify-totp` (server-side only)

### Database

- PostgreSQL 16 with SQLAlchemy (async)
- Alembic for migrations
- Key tables: users, roles, findings (per tool), runs, sources, app config, audit events
- Role cache: 60s TTL, invalidated on mutation

### Object Storage

- MinIO (S3-compatible) for scan artifacts
- Prefixes: `dependencies/`, `code_scanning/`, `secrets/`, `container_scanning/`
- SBOMs stored separately in `sboms/` bucket
- Runner service account scoped to `scans/*` and `sboms/*` only

### Encryption

- `shared/encryption.py` — Fernet encryption for sensitive data at rest
- Source connection auth tokens and TOTP secrets encrypted in the database
- Job environment variables encrypted with PBKDF2 key derivation (100k rounds)

### Rate Limiting

- `shared/rate_limit.py` — per-endpoint rate limits
- Scan initiation: 5 requests per 5 minutes
- Runner registration: 5 requests per 5 minutes
- AI review: 10 requests per minute

## Frontend

### Routing

The frontend uses Next.js app router with this layout:

```
app/
├── (app)/              # Authenticated layout (sidebar + main content)
│   ├── home/           # Home dashboard
│   ├── dependencies/   # /dependencies
│   ├── containers/     # /containers
│   ├── code/           # /code
│   ├── secrets/        # /secrets
│   ├── sources/        # Source management
│   ├── settings/       # Settings pages
│   └── notifications/  # Notification center
├── api/                # BFF proxy routes
└── login/              # Unauthenticated login page
```

### BFF Proxy

The Next.js API routes act as a Backend-For-Frontend proxy:
- `/api/dependencies/*` → `/dependencies/api/*`
- `/api/code/*` → `/code-scanning/api/*`
- `/api/containers/*` → `/container-scanning/api/*`
- `/api/secrets/*` → `/secrets/api/*`

This keeps the backend URL structure internal and handles auth token forwarding.

### Real-Time Updates (SSE)

- `SSEProvider` in the app shell provides real-time event streaming
- Backend publishes events via `EventBus` (in-memory pub/sub) at `/events/api/stream`
- Events: `scan.progress`, `scan.completed`, `scan.failed`, `source.synced`, `runner.status`, `notification.new`
- `BroadcastChannel` for leader election across browser tabs (only one SSE connection per browser)
- Automatic fallback to polling after 3 consecutive SSE failures
- 30-second heartbeat interval

### Tool Dashboards

Every tool follows the same 5-tab pattern:
1. **Overview** — summary cards, charts, severity breakdown
2. **Findings** — filterable table with finding details
3. **Insights** — analytics and trends
4. **Health** — scan run history and status
5. **Settings** — tool configuration

Dashboard prerequisites check: if no source is configured or verified, the user is directed to the Settings tab first.

### Theming

- CSS custom properties in `app/globals.css`
- Severity tokens: `--color-severity-critical`, `--color-severity-high`, `--color-severity-medium`, `--color-severity-low`
- Dark and light themes with `ThemeProvider`
- Space Grotesk (headings), Inter (body), JetBrains Mono (code)

## Scanner Pipeline

### Lifecycle of a Scan

```
1. User clicks "Scan" in the UI
       │
2. Backend creates a run record (status: queued)
       │
3. Runner polls for jobs, picks up the run
       │
4. Runner launches scanner Docker container
   ┌──────────────────────────────────────┐
   │  Scanner container:                  │
   │  1. Clone repo / pull image          │
   │  2. Run scanning tools               │
   │  3. Normalize output to JSON         │
   │  4. Generate manifest                │
   │  5. Write results to shared volume   │
   └──────────────────────────────────────┘
       │
5. Runner streams progress events via SSE
       │
6. Runner uploads results to MinIO
       │
7. Backend ingests findings, applies lifecycle
   (new findings → open, missing findings → fixed)
       │
8. Notifications emitted for critical findings
```

### Scanner Images

Each scanner is a Docker image built from `scanners/<tool>/Dockerfile`:

| Scanner | Image | Tools |
|---|---|---|
| Dependencies | `aegis/scanner-dependencies` | Syft, Grype, grype-db, cdxgen, CycloneDX CLI |
| Code Scanning | `aegis/scanner-code-scanning` | Semgrep, tree-sitter, semgrep-rules |
| Secrets | `aegis/scanner-secrets` | TruffleHog |
| IaC | `aegis/scanner-iac` | Checkov |
| Container | `aegis/scanner-container` | Syft, Grype |

Each image has a signature label (`io.aegis.security.<tool>.signature`) validated by the runner before use.

### Image Management

The runner's `image_manager.py` handles:
- **Auto-build** from `scanners/` directory if present
- **Registry pull** from GHCR as fallback
- **Label validation** to ensure image integrity
- Source priority: `SCANNER_IMAGE_SOURCE` env var (`auto`, `local`, `registry`)

## Runner

The runner is a standalone Python process that:

1. Registers with the backend using `RUNNER_REGISTRATION_TOKEN`
2. Builds/pulls scanner Docker images on startup
3. Polls for scan jobs from the backend job queue
4. Executes scans in Docker containers with:
   - Shared volume for results
   - Encrypted environment variables
   - Resource limits
5. Streams progress via SSE (signal-driven: immediate on scan events, not just timer-based)
6. Uploads results to MinIO
7. Reports heartbeat with image status

### Security

- Git clone restricted to HTTPS only
- Commit hashes validated (hex 7-64 chars)
- File paths validated against directory traversal
- SSRF validation on container registry hosts
- MinIO access scoped to `scans/*` and `sboms/*`

## Notifications

Event-driven notification system:
- `emitter.py` provides: `notify_scan_completed`, `notify_scan_failed`, `notify_new_critical_findings`, `notify_runner_offline`, `notify_source_synced`
- New findings trigger notifications when lifecycle detection identifies them
- `NotificationBell` component uses SSE `notification.new` events for real-time count updates

## Source Management

Sources are external connections (Git repositories, container registries, cloud infrastructure):
- Category normalization: frontend uses `container-registry`, backend normalizes to `container-images`
- Source connections store encrypted auth tokens
- Auto-sync discovers repositories and images from connected sources
- Team-based scoping: teams own repositories and container images, users see findings based on team membership
