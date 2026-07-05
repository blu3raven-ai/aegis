# Development Guide

This guide covers setting up Aegis for local development.

## Prerequisites

- **Python 3.11+** with pip or [uv](https://docs.astral.sh/uv/)
- **Node.js 20+** with npm
- **Docker** and **Docker Compose** (for PostgreSQL, MinIO, and the runner)
- **Git**

## Quick Start (Docker Compose)

The fastest way to get everything running:

```bash
cp .env.example .env
# Edit .env — replace all "change-me" values

docker compose up -d
```

This starts: PostgreSQL, MinIO (object storage), the unified Aegis container (FastAPI + static Next.js export on port 3000), and the runner with all scanners bundled.

## Manual Development Setup

For active development, run the frontend and backend outside Docker for hot-reload.

### 1. Database and Object Storage

Start only the infrastructure services:

```bash
docker compose up -d postgres minio
```

### 2. Backend

```bash
cd backend
pip install -e .

# Or with uv:
# uv pip install -e .

DATABASE_URL=postgresql+asyncpg://app:app@localhost:5432/app \
  uvicorn src.main:app --reload --port 8000
```

Or use the npm script (from `frontend/`):

```bash
cd frontend && npm run dev:backend
```

The backend serves the REST API at `http://localhost:8000/api/v1/` and GraphQL at `http://localhost:8000/api/v1/graphql`.

### 3. Frontend

```bash
cd frontend
npm install
npm run dev
```

The frontend is available at `http://localhost:3000`. The Next.js proxy forwards API requests to the backend automatically.

### 4. Runner (optional)

The runner executes scan jobs. It requires scanner CLIs installed locally (Syft, Grype, Semgrep, TruffleHog, Checkov) or can use the bundled runner Docker image.

```bash
cd runner
uv sync
uv run python main.py
```

The runner registers with the backend and polls for scan jobs.

### 5. Start Everything

```bash
cd frontend && npm run dev:all    # starts backend + frontend concurrently
```

## Environment Variables

Copy `.env.example` to `.env` and configure:

| Variable | Description |
|---|---|
| `APP_SECRET` | Root key for all at-rest encryption. Use `openssl rand -base64 32`. Keep stable — rotating it makes stored secrets unreadable. |
| `SESSION_SECRET` | Signs browser session cookies. Required — startup fails if missing. |
| `ALLOWED_HOSTS` | Comma-separated list of allowed hostnames for TrustedHostMiddleware (e.g. `localhost,127.0.0.1`). |
| `ADMIN_PASSWORD` | Initial admin account password. |
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` | Database credentials. |
| `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` | Object storage credentials. |
| `RUNNER_NAME` | Runner display name. |
| `RUNNER_REGISTRATION_TOKEN` | Runner ↔ backend authentication token. |

## Running Tests

### Backend

```bash
cd backend && python -m pytest src/tests/ -v
```

### Frontend

```bash
cd frontend && npm run test
```

### E2E Tests

```bash
cd frontend && npm run test:e2e
```

Requires Playwright installed (`npx playwright install`).

## Project Structure

```
aegis/
├── frontend/                   Next.js application
│   ├── app/                    Next.js app router
│   │   ├── (app)/              Authenticated app pages
│   │   │   ├── overview/       Home dashboard
│   │   │   ├── findings/       Unified findings view
│   │   │   ├── sources/        Source management
│   │   │   ├── inventory/      Asset inventory
│   │   │   ├── posture/        Posture scoring
│   │   │   ├── compliance/     Compliance framework mapping
│   │   │   ├── sbom/           SBOM browser and diff
│   │   │   ├── history/        Event feed
│   │   │   ├── settings/       Settings pages
│   │   │   └── workspace/      Users, roles, teams
│   │   ├── api/                Next.js API routes (BFF proxy)
│   │   └── login/              Login page
│   ├── components/             React components
│   │   ├── ui/                 Shared primitives (Button, NavTabs, FilterChip, etc.)
│   │   ├── shared/             Domain-shared components (findings, sources, rules)
│   │   └── layout/             AppShell, Sidebar, AppHeader
│   ├── lib/                    Shared TypeScript code
│   ├── public/                 Static assets
│   ├── middleware.ts            Next.js middleware
│   ├── next.config.ts          Next.js configuration
│   ├── package.json            Frontend dependencies + scripts
│   └── tsconfig.json           TypeScript configuration
│
├── backend/                    FastAPI backend
│   └── src/
│       ├── auth/               Authentication, SSO, MFA, SCIM
│       ├── authz/              Permission catalog, enforcement, scope
│       ├── findings/           Unified findings API and lifecycle
│       ├── scans/              Scan orchestration and job dispatch
│       ├── code_scanning/      SAST module
│       ├── containers/         Container scanning module
│       ├── dependencies/       SCA module
│       ├── secrets/            Secrets scanning module
│       ├── iac/                IaC scanning module
│       ├── agent_scanning/     Agent-threat scanning module
│       ├── osv/                OSV advisory mirror
│       ├── epss/               EPSS ingestion
│       ├── kev/                CISA KEV ingestion
│       ├── posture/            Posture scoring
│       ├── sla/                SLA tracking
│       ├── compliance/         Framework control mapping
│       ├── sbom/               SBOM export and browser
│       ├── notifications/      Notification system
│       ├── runner/             Runner management
│       ├── settings/           Settings and configuration
│       ├── graphql/            Strawberry GraphQL schema
│       ├── shared/             Shared utilities
│       └── db/                 Database models and migrations
│
├── runner/                     Scanner job runner
│   ├── main.py                 Runner entry point
│   └── scanners/
│       ├── code_scanning/      Semgrep + tree-sitter (with LLM verification)
│       ├── secrets/            TruffleHog
│       ├── iac/                Checkov (with LLM verification)
│       ├── container/          Syft + Grype
│       ├── dependencies/       Syft + Grype + OSV matching
│       ├── agent/              Agent-threat detection (in-process)
│       └── _shared.py          Shared LLM client and budget utilities
│
├── integrations/               CI/CD artifacts
│   ├── github-action/          GitHub Action
│   ├── gitlab-component/       GitLab CI Component
│   ├── bitbucket-pipe/         Bitbucket Pipe
│   ├── azure-devops-task/      Azure DevOps Task
│   └── jenkins-shared-library/ Jenkins Shared Library
│
├── docker-compose.yml          Full-stack Docker Compose
├── Dockerfile                  Combined Aegis container (frontend + backend)
├── .env.example                Environment variable template
└── docs/
    ├── architecture.md         System architecture (this file's sibling)
    └── development.md          This file
```

## Common Tasks

### Adding a new scanner module

1. **Runner scanner** — `runner/scanners/<name>/` with a `scanner.py` entry point that accepts a `JobEnv` and uploads results to MinIO
2. **Backend ingest** — `backend/src/<name>/` with `ingest.py`, `lifecycle.py`, `scanner.py` (orchestration), and a REST router
3. **Frontend pages** — `frontend/app/(app)/<name>/` with the findings table and scanner detail views
4. **GraphQL** — add a resolver inside the relevant namespace type in `backend/src/graphql/schema.py` or the bounded-context resolver file
5. **Tests** — `backend/src/tests/test_<name>*.py` and frontend tests alongside the components

### Resetting the database

```bash
docker compose down -v    # removes volumes including database
docker compose up -d
```

### Running Alembic migrations

```bash
cd backend
alembic upgrade head
```

To generate a new migration after model changes:

```bash
alembic revision --autogenerate -m "short description"
# Review the generated file
# Replace downgrade() body with: raise NotImplementedError("Forward-only; no downgrade.")
```
