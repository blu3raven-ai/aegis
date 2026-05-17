# Development Guide

This guide covers setting up Aegis for local development.

## Prerequisites

- **Python 3.11+** with pip or [uv](https://docs.astral.sh/uv/)
- **Node.js 20+** with npm
- **Docker** and **Docker Compose** (for scanners, PostgreSQL, MinIO)
- **Git**

## Quick Start (Docker Compose)

The fastest way to get everything running:

```bash
cp .env.example .env
# Edit .env — replace all "change-me" values

docker compose up -d
```

This starts: PostgreSQL, MinIO (object storage), backend, frontend, and runner with all scanners.

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

Or use the npm script:

```bash
npm run dev:backend
```

The backend serves the REST API at `http://localhost:8000` and GraphQL at `http://localhost:8000/graphql/api`.

### 3. Frontend

```bash
npm install
npm run dev
```

The frontend is available at `http://localhost:3000`. The Next.js proxy forwards API requests to the backend automatically.

### 4. Runner (optional)

The runner executes scan jobs. It requires Docker to build and run scanner images.

```bash
cd runner
pip install -r requirements.txt
python main.py
```

The runner registers with the backend, builds scanner Docker images from `scanners/`, and polls for scan jobs.

### 5. Start Everything

```bash
npm run dev:all    # starts backend + frontend concurrently
```

## Environment Variables

Copy `.env.example` to `.env` and configure:

| Variable | Description |
|---|---|
| `JWT_SHARED_SECRET` | Signs API tokens (frontend ↔ backend). Use `openssl rand -base64 32`. |
| `SESSION_SECRET` | Signs browser session cookies. |
| `ADMIN_PASSWORD` | Initial admin account password. |
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` | Database credentials. |
| `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` | Object storage credentials. |
| `RUNNER_NAME` | Runner display name. |
| `RUNNER_REGISTRATION_TOKEN` | Runner ↔ backend authentication token. |

Tool-specific variables (e.g., `SCA_ENABLED`, `SAST_DOCKER_IMAGE`) can be configured through the Settings UI or `.env`.

## Running Tests

### Backend

```bash
npm run test:backend
# or directly:
cd backend && python -m pytest ../tests/backend/ -v --rootdir=.
```

### Frontend

```bash
npm run test:frontend
# or directly:
node --test tests/frontend/*.test.ts
```

### Contract Tests

```bash
npm run test:contracts
```

### E2E Tests

```bash
npm run test:e2e
```

Requires Playwright installed (`npx playwright install`).

## Project Structure

```
aegis/
├── app/                        Next.js app router
│   ├── (app)/                  Authenticated app pages
│   │   ├── home/               Home dashboard
│   │   ├── dependencies/       Dependencies tool
│   │   ├── containers/         Container scanning tool
│   │   ├── code/               Code scanning tool
│   │   ├── secrets/            Secrets tool
│   │   ├── sources/            Source management (Git, registries)
│   │   ├── settings/           Settings pages
│   │   └── notifications/      Notification center
│   ├── api/                    Next.js API routes (BFF proxy layer)
│   └── login/                  Login page
│
├── backend/                    FastAPI backend
│   └── src/
│       ├── auth/               Authentication and authorization
│       ├── code_scanning/      Code scanning module
│       ├── containers/         Container scanning module
│       ├── dependencies/       Dependencies (SCA) module
│       ├── secrets/            Secrets scanning module
│       ├── graphql/            Strawberry GraphQL schema
│       ├── notifications/      Notification system
│       ├── runner/             Runner management
│       ├── settings/           Settings and configuration
│       ├── shared/             Shared utilities (config, encryption, rate limiting)
│       ├── db/                 Database models and helpers
│       └── license/            License verification
│
├── runner/                     Scanner job runner
│   ├── main.py                 Runner entry point
│   └── image_manager.py        Scanner image build/pull/validation
│
├── scanners/                   Scanner Docker images
│   ├── dependencies/           Syft + Grype + cdxgen
│   ├── code-scanning/          Opengrep + tree-sitter
│   ├── secrets/                TruffleHog + BetterLeaks + ONNX classifier
│   ├── container/              Syft + Grype (container images)
│   └── shared/                 Shared scanner utilities (manifest, lib.sh)
│
├── components/                 React components
│   ├── providers/              Context providers (SSE, theme)
│   └── shared/                 Shared UI components
│
├── lib/                        Shared TypeScript code
│   ├── server/                 Server-side utilities (app config)
│   └── shared/                 Client/server shared utilities
│
├── tests/
│   ├── backend/                Python backend tests (pytest)
│   ├── frontend/               Frontend unit tests (node:test)
│   ├── contracts/              API contract tests
│   └── e2e/                    Playwright end-to-end tests
│
├── docker-compose.yml          Full-stack Docker Compose
├── .env.example                Environment variable template
└── docs/
    ├── README.md               This file
    └── architecture.md         System architecture deep dive
```

## Common Tasks

### Adding a new tool module

Each scanning tool follows the same pattern:

1. **Scanner** — `scanners/<tool>/` with Dockerfile, `run.sh`, and scripts
2. **Backend module** — `backend/src/<tool>/` with router, scanner, store
3. **Frontend pages** — `app/(app)/<tool>/` with dashboard tabs
4. **GraphQL** — types and resolvers in `backend/src/graphql/`
5. **Tests** — `tests/backend/test_<tool>.py` and `tests/frontend/<tool>.test.ts`

### Resetting the database

```bash
docker compose down -v    # removes volumes including database
docker compose up -d
```

### Rebuilding scanner images

Scanner images are built automatically by the runner on startup. To force a rebuild:

```bash
docker rmi aegis/scanner-dependencies:latest aegis/scanner-code-scanning:latest \
           aegis/scanner-secrets:latest aegis/scanner-container:latest
# Restart the runner — it will rebuild
```
