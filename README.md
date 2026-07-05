<p align="center">
  <img src="public/logo-brand.png" alt="Aegis" width="80" />
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

- **Scans everything** — dependencies, containers, source code, secrets, and infrastructure from one interface
- **Tracks findings over time** — automated lifecycle management detects new, fixed, and recurring vulnerabilities across every scan
- **Keeps data on your infrastructure** — no telemetry, no cloud dependencies, no external API calls at runtime
- **Works out of the box** — `git clone`, `docker compose up`, add a GitHub PAT, and start scanning in minutes
- **Scales with your team** — role-based access, team-based repository scoping, and real-time dashboards that update as scans progress

Whether you're a solo developer running your first security scan or an enterprise security team triaging thousands of findings across hundreds of repositories, Aegis gives you a clear, actionable view of your vulnerability posture.

## Features

### Scanning Tools

| Tool | Scanner | What It Does |
|---|---|---|
| **Dependencies** | Syft + Grype | Generates Software Bill of Materials (SBOM) for every repository, matches against NVD and GHSA advisory databases, tracks open/fixed/dismissed findings across scans |
| **Containers** | Syft + Grype | Scans container images from registries (GHCR, Docker Hub), detects known CVEs in OS packages and application dependencies, skips unchanged images via digest checking |
| **Code Scanning** | Semgrep | Static analysis (SAST) with OWASP/CWE rulesets, LLM-based exploit-chain verification (hunter + skeptic) to reduce false positives, call-graph reachability analysis to confirm exploitability |
| **Secrets** | TruffleHog | Detects leaked credentials, API keys, and tokens in code history. LLM verification gate (hunter + skeptic) drops test/fixture matches. Contextual enrichment shows surrounding code |
| **IaC Security** | Checkov | Detects misconfigurations in Terraform, CloudFormation, Kubernetes manifests, and other IaC formats |

### Platform Capabilities

- **Real-time scanning** — live progress via Server-Sent Events with automatic polling fallback
- **GraphQL API** — unified query layer for dashboards, analytics, and filtering across all tools
- **Role-based access control** — granular permissions (view findings, initiate scans, manage settings, etc.)
- **Team-based scoping** — organize users into teams with repository and container image access boundaries
- **Finding lifecycle** — automated state management: open → fixed / dismissed / awaiting fix
- **Source management** — connect Git repositories, container registries, and cloud infrastructure as scan targets
- **Notification system** — real-time alerts for critical findings, scan completions, and runner status changes
- **Dark and light themes** — full theme support designed for extended security triage sessions
- **CI/CD integration** — trigger scans from GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure DevOps, or Jenkins; sticky PR comments back to the merge request

### Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 15 (App Router), React, TypeScript, Tailwind CSS |
| Backend | FastAPI (async Python), Strawberry GraphQL, SQLAlchemy |
| Database | PostgreSQL 16 |
| Object Storage | MinIO (S3-compatible) — SBOMs, scan artifacts |
| Scanners | Embedded in runner image — Syft, Grype, cdxgen, Semgrep, TruffleHog, Checkov |
| AI | OpenAI-compatible LLM gateway (BYO key) — hunter/skeptic verification, mechanical citation critic |
| Real-time | Server-Sent Events (SSE) with BroadcastChannel leader election |

### Editions

| | Community | Enterprise |
|---|---|---|
| **Price** | Free | Paid |
| **All scanning tools** | ✅ | ✅ |
| **No user/repo limits** | ✅ | ✅ |
| **SSO & MFA** | — | ✅ |
| **Audit logs** | — | ✅ |
| **Integrations** | — | ✅ |

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
├── app/              Next.js app router (frontend)
├── backend/          FastAPI backend (Python)
│   └── src/
│       ├── auth/           Authentication & authorization
│       ├── dependencies/   SCA scanning module
│       ├── code_scanning/  SAST scanning module
│       ├── containers/     Container scanning module
│       ├── secrets/        Secret detection module
│       ├── graphql/        Strawberry GraphQL schema
│       ├── notifications/  Event-driven notifications
│       ├── runner/         Runner management & job queue
│       ├── settings/       Configuration & team management
│       └── shared/         Config, encryption, rate limiting
├── runner/           Scanner job runner with embedded scanner modules
│   └── scanners/
│       ├── dependencies/     Syft + Grype + cdxgen
│       ├── code_scanning/    Semgrep + tree-sitter (with LLM verification)
│       ├── secrets/          TruffleHog (with LLM verification)
│       ├── iac/              Checkov
│       └── container/        Syft + Grype
├── components/       Shared React components
├── lib/              Shared TypeScript utilities
└── tests/            Backend, frontend, contract, and e2e tests
```

## Roadmap

- [ ] IaC Security scanner
- [ ] DAST (Dynamic Application Security Testing)
- [ ] Remote runners
- [ ] SSO integration (SAML, OIDC)
- [ ] Audit log
- [ ] Webhook & ticketing integrations (Jira, Slack, PagerDuty)
- [ ] CI/CD pipeline integration
- [ ] API key management

## FAQ

<details>
<summary><strong>How long does the first startup take?</strong></summary>

The first `docker compose up` builds the runner image, which bundles all scanner CLIs and Python dependencies. This can take several minutes depending on your internet speed and machine. Subsequent startups are fast since the image is cached.
</details>

<details>
<summary><strong>Can I run Aegis without Docker?</strong></summary>

The frontend and backend can run natively (Node.js + Python). The runner can also run natively if all scanner CLIs (Syft, Grype, cdxgen, Semgrep, TruffleHog, Checkov) and Python dependencies are installed locally — see [docs/development.md](docs/development.md).
</details>

<details>
<summary><strong>How do I connect my GitHub repositories?</strong></summary>

Go to **Sources → Git Repositories** in the sidebar, click **Add Source**, and enter your GitHub organization and a personal access token (PAT) with `repo` scope. Aegis will discover all repositories in the organization.
</details>

<details>
<summary><strong>What happens to my data?</strong></summary>

Everything stays on your infrastructure. Scan results are stored in PostgreSQL and MinIO. No telemetry, no cloud calls, no external dependencies at runtime.
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

<details>
<summary><strong>What's the difference between Community and Enterprise?</strong></summary>

Community is the full product with no feature limits. Enterprise adds organizational infrastructure — SSO, MFA, audit logs, and third-party integrations — for companies that need governance and compliance controls.
</details>

## Production Configuration

### Feature flags (env vars)

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_CORRELATION_ENABLED` | `false` | Enable the correlation engine on app startup |
| `JOB_QUEUE_BACKEND` | `file` | `file` / `postgres` |
| `MULTI_ORG_CONCURRENCY` | `8` | Max concurrent orgs in scan orchestration |
| `AEGIS_CORRELATION_EPSS_THRESHOLD` | `0.7` | EPSS threshold for severity escalation rule |
| `ARGUS_ENDPOINT` | (unset) | Argus connector endpoint URL |
| `ARGUS_API_KEY` | (unset) | Argus API key |
| `ARGUS_WEBHOOK_SECRET` | (unset) | HMAC secret for Argus → Aegis webhooks |

### Health endpoints

- `GET /health` — full component status
- `GET /health/ready` — k8s readiness probe
- `GET /health/live` — k8s liveness probe

### Suggested rollout

1. **Phase 0 (default):** Existing behavior, all features dormant. Validates deployment.
2. **Phase 1:** Switch `JOB_QUEUE_BACKEND=postgres`. Validates the Postgres queue backend.
3. **Phase 2:** Existing scanner ingest with per-scanner baseline+delta engines (dormant until wired per scanner).
4. **Phase 3–4:** `AEGIS_CORRELATION_ENABLED=true` + Argus config. Attack chains materialize; AI scoring enriches findings.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting issues, pull requests, and code style.

## License

Aegis is licensed under the [Business Source License 1.1](LICENSE). You can use, modify, and self-host freely. The only restriction is offering it as a competing commercial hosted service. Each version converts to Apache-2.0 after 4 years.
