<p align="center">
  <img src="frontend/public/logo-brand.png" alt="Aegis" width="80" />
</p>

<h1 align="center">Aegis</h1>
<p align="center">
  <strong>Self-hosted vulnerability management portal</strong>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="docs/development.md">Development</a> •
  <a href="docs/architecture.md">Architecture</a> •
  <a href="CONTRIBUTING.md">Contributing</a> •
  <a href="SECURITY.md">Security</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-BSL--1.1-blue" alt="License" />
  <img src="https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white" alt="Python 3.11+" />
  <img src="https://img.shields.io/badge/node-20+-339933?logo=node.js&logoColor=white" alt="Node.js 20+" />
  <img src="https://img.shields.io/badge/next.js-15-black?logo=next.js" alt="Next.js 15" />
  <img src="https://img.shields.io/badge/fastapi-0.115-009688?logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen" alt="PRs Welcome" />
</p>

---

## Why Aegis?

Most security teams juggle multiple disconnected scanners — each with its own CLI, output format, and dashboard. Findings live in scattered JSON files, spreadsheets, or SaaS platforms that require sending your code to a third party.

Aegis replaces that with a single self-hosted portal that:

- **Scans everything** — dependencies, containers, source code, secrets, infrastructure, and AI-agent attack surfaces from one interface
- **Tracks findings over time** — automated lifecycle management detects new, fixed, and recurring vulnerabilities across every scan
- **Keeps data on your infrastructure** — no telemetry, no cloud dependencies, no external API calls at runtime
- **Works out of the box** — `git clone`, `docker compose up`, add a GitHub PAT, and start scanning in minutes
- **Scales with your team** — role-based access, team-based repository scoping, and real-time dashboards that update as scans progress

Whether you're a solo developer running your first security scan or an enterprise security team triaging thousands of findings across hundreds of repositories, Aegis gives you a clear, actionable view of your vulnerability posture.

## Features

### Scanning Tools

| Tool | Scanner | What It Does |
|---|---|---|
| **Dependencies** | Syft + Grype | Generates Software Bill of Materials (SBOM) for every repository, matches against OSV advisory mirror (NVD, GHSA, and more), tracks open/fixed/dismissed findings across scans, reachability analysis to confirm exploitability |
| **Containers** | Syft + Grype | Scans container images from registries (GHCR, Docker Hub), detects known CVEs in OS packages and application dependencies, layer attribution, base-image tag recommendations |
| **Code Scanning** | Semgrep | Static analysis (SAST) with OWASP/CWE rulesets, LLM-based TP-reasoning and FP-detection chains to reduce false positives, call-graph reachability analysis |
| **Secrets** | TruffleHog | Detects leaked credentials, API keys, and tokens in code history; TruffleHog provider verification; contextual code windows |
| **IaC Security** | Checkov | Detects misconfigurations in Terraform, CloudFormation, Kubernetes manifests, and other IaC formats; diff-scoped scanning on PRs |
| **Agent Scanning** | Pure Python | Detects AI-agent-targeted attacks in repositories: unicode bidirectional overrides, config-key injection, skill-bundle hijacking, LLM-judge poisoning, encoded payloads, homoglyphs, and exfil instructions. No external binary required. |

### Platform Capabilities

- **Real-time scanning** — live progress via Server-Sent Events with automatic polling fallback
- **Attack chain graph** — correlates findings from multiple scanners into exploitable chains (react-flow visualization)
- **OSV advisory mirror** — backend-native vulnerability matching against a local copy of OSV, KEV, and EPSS data; no internet required per scan
- **SBOM export** — CycloneDX and SPDX formats; browser, diff view, and boolean search grammar for advisory triage
- **Posture scoring** — configurable severity weights, band multipliers, and gauge thresholds; Overview and Triage tabs
- **Compliance mapping** — SOC 2, ISO 27001, and PCI DSS controls mapped to findings; attestation report templates
- **SLA tracking** — configurable deadlines per severity; automatic violation detection; rule engine for policy enforcement
- **GraphQL + REST API** — unified query layer for dashboards and analytics; REST for mutations and CI/CD
- **Role-based access control** — granular permissions with declarative gates on every endpoint
- **Team-based scoping** — organize users into teams with repository and container image access boundaries
- **Finding lifecycle** — automated state management: open → fixed / dismissed / awaiting fix; assignment; audit trail
- **Source management** — connect Git repositories, container registries, and cloud infrastructure as scan targets
- **Notification system** — real-time alerts via Slack and webhooks; inbox with delivery history; routing rules
- **Audit log** — auto-recorded admin and mutation events; viewer under Settings
- **SSO** — SAML and OIDC with JIT provisioning and SCIM sync
- **CI/CD integration** — GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure DevOps, Jenkins; sticky PR comments back to the merge request
- **Dark and light themes** — full theme support designed for extended security triage sessions
- **BYO LLM verification** — connect any OpenAI-compatible endpoint; hunter + skeptic chains for SAST, IaC, and agent findings; optional frontier escalation tier

### Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 15 (App Router), React, TypeScript, Tailwind CSS v4 |
| Backend | FastAPI (async Python), Strawberry GraphQL, SQLAlchemy |
| Database | PostgreSQL 16 |
| Object Storage | MinIO (S3-compatible) — SBOMs, scan artifacts |
| Scanners | Bundled in runner — Syft, Grype, Semgrep, TruffleHog, Checkov; Agent scanner runs in-process |
| AI | OpenAI-compatible LLM gateway (BYO key) — TP-reasoning and FP-detection chains; optional frontier escalation |
| Real-time | Server-Sent Events (SSE) with BroadcastChannel leader election |

## Requirements

| Resource | Minimum | Recommended |
|---|---|---|
| **CPU** | 2 cores | 4+ cores |
| **RAM** | 4 GB | 8+ GB |
| **Disk** | 10 GB | 20+ GB (runner image + scan artifacts + Grype DB cache) |
| **Docker** | 20.10+ | Latest stable |
| **Docker Compose** | v2.0+ | Latest stable |

> All scanner tooling is bundled directly into the runner image — no Docker socket mount, no privileged access, no per-scanner container builds. The runner, backend, and frontend containers use 2 GB, 2 GB, and 1 GB memory limits respectively.

## Quick Start

```bash
git clone https://github.com/blu3raven-ai/aegis.git
cd aegis
cp .env.example .env
docker compose up -d
```

That's it. Open http://localhost:3000 and log in with `admin` / `admin`.

To start scanning, go to **Sources**, add a GitHub Personal Access Token (PAT), and Aegis will discover and scan all your repositories automatically.

> The first startup builds a single runner image bundling all scanner CLIs. Subsequent startups are fast.

### Production

For production deployments, replace all default secrets in `.env` with strong random values:

```bash
openssl rand -base64 32
```

Also recommended: deploy a reverse proxy (nginx, Caddy, Traefik) with TLS and restrict database/MinIO ports to internal networks.

## Development

See [docs/development.md](docs/development.md) for the full development setup guide, including running without Docker, environment variables, and testing.

## Architecture

See [docs/architecture.md](docs/architecture.md) for a deep dive into the system design.

```
├── frontend/         Next.js app router (frontend)
├── backend/          FastAPI backend (Python)
│   └── src/
│       ├── auth/           Authentication & authorization
│       ├── authz/          Permission catalog, enforcement, scope
│       ├── findings/       Unified findings API and lifecycle
│       ├── scans/          Scan orchestration and job dispatch
│       ├── dependencies/   SCA scanning module
│       ├── code_scanning/  SAST scanning module
│       ├── containers/     Container scanning module
│       ├── secrets/        Secret detection module
│       ├── iac/            IaC scanning module
│       ├── agent_scanning/ Agent-threat scanning module
│       ├── osv/            OSV advisory mirror and matching
│       ├── epss/           EPSS ingestion and enrichment
│       ├── kev/            CISA KEV ingestion and enrichment
│       ├── posture/        Posture scoring and trend resolvers
│       ├── sla/            SLA tracking and violation engine
│       ├── compliance/     Framework and control mapping
│       ├── sbom/           SBOM export and browser
│       ├── graphql/        Strawberry GraphQL schema
│       ├── notifications/  Event-driven notifications
│       ├── runner/         Runner management & job queue
│       ├── settings/       Configuration & team management
│       └── shared/         Config, encryption, rate limiting
├── runner/           Scanner job runner with embedded scanner modules
│   └── scanners/
│       ├── code_scanning/    Semgrep + tree-sitter (with LLM verification)
│       ├── secrets/          TruffleHog
│       ├── iac/              Checkov (with LLM verification)
│       ├── container/        Syft + Grype
│       ├── dependencies/     Syft + Grype + OSV matching
│       ├── agent/            Agent-threat detection (in-process)
│       └── _shared.py        Shared LLM client and scan budget utilities
├── integrations/     CI/CD artifacts (GitHub Action, GitLab CI Component, etc.)
└── tests/            E2E tests (Playwright)
```

## Roadmap

The following capabilities are partially built or catalogued but not yet fully wired through:

- [ ] **Fix PR generation** — auto-open a pull request with a dependency upgrade or remediation patch for a finding
- [ ] **Jira / Linear / GitHub Issues ticketing** — auto-create tickets for new findings (connector catalog entries exist; delivery not yet wired)
- [ ] **Microsoft Teams / PagerDuty / Email Digest notifications** — additional notification channels (connector catalog entries exist; delivery not yet wired)
- [ ] **SLA escalations** — notify a channel before a deadline is breached (rule engine supports escalation legs; delivery not yet wired)
- [ ] **Notification digest preferences** — weekly summary and product-update emails
- [ ] **DAST** — dynamic application security testing

## FAQ

<details>
<summary><strong>How long does the first startup take?</strong></summary>

The first `docker compose up` builds the runner image, which bundles all scanner CLIs and Python dependencies. This can take several minutes depending on your internet speed and machine. Subsequent startups are fast since the image is cached.
</details>

<details>
<summary><strong>Can I run Aegis without Docker?</strong></summary>

The frontend and backend can run natively (Node.js + Python). The runner can also run natively if all scanner CLIs (Syft, Grype, Semgrep, TruffleHog, Checkov) and Python dependencies are installed locally — see [docs/development.md](docs/development.md).
</details>

<details>
<summary><strong>How do I connect my GitHub repositories?</strong></summary>

Go to **Sources** in the sidebar, click **Add Source**, and enter your GitHub organization and a personal access token (PAT) with `repo` scope. Aegis will discover all repositories in the organization.
</details>

<details>
<summary><strong>What happens to my data?</strong></summary>

Everything stays on your infrastructure. Scan results are stored in PostgreSQL and MinIO. No telemetry, no cloud calls, no external dependencies at runtime. The OSV advisory mirror is bootstrapped once and refreshed nightly — no per-scan internet access needed.
</details>

<details>
<summary><strong>How do I update Aegis?</strong></summary>

```bash
git pull
docker compose down
docker compose up -d --build
```

The runner image is rebuilt by `docker compose up -d --build` when the runner Dockerfile or sources change.
</details>

<details>
<summary><strong>The scan is stuck in "queued" — what do I check?</strong></summary>

1. Check that the runner is running: `docker compose logs runner`
2. The first run downloads Grype's vulnerability database into the `aegis-grype-cache` volume — this can take a few minutes
3. If the runner keeps restarting, check `RUNNER_REGISTRATION_TOKEN` matches in both runner and backend configs
</details>

<details>
<summary><strong>How do I reset everything and start fresh?</strong></summary>

```bash
docker compose down -v    # removes all volumes (database, MinIO, Grype DB cache)
docker compose up -d
```

This deletes all data including findings, runs, and uploaded SBOMs.
</details>

## Production Configuration

### Key environment variables

| Variable | Purpose |
|---|---|
| `APP_SECRET` | Root key for all at-rest encryption. Use `openssl rand -base64 32`. Keep stable — rotating it makes stored secrets unreadable. |
| `SESSION_SECRET` | Signs browser session cookies. Required — startup fails if missing. |
| `ALLOWED_HOSTS` | Comma-separated allowed hostnames for TrustedHostMiddleware. |
| `ADMIN_PASSWORD` | Initial admin account password. |
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` | Database credentials. |
| `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` | Object storage credentials. |
| `RUNNER_REGISTRATION_TOKEN` | Runner ↔ backend authentication token. |

### Health endpoints

- `GET /health` — full component status
- `GET /health/ready` — k8s readiness probe
- `GET /health/live` — k8s liveness probe

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting issues, pull requests, and code style.

## License

Aegis is licensed under the [Business Source License 1.1](LICENSE). You can use, modify, and self-host freely. The only restriction is offering it as a competing commercial hosted service. Each version converts to Apache-2.0 after 4 years.
