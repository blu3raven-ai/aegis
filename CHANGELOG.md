# Changelog

All notable changes to this project are documented here.

---

## v2.6.0 — 2026-07-07

### Security

- Disabled accounts are now rejected at the session gate and at login, and their active sessions are revoked immediately on disable
- Password resets, role changes, and account disable now terminate the affected user's existing sessions
- Scheduled reports enforce owner and asset-scope checks on read, update, and delete; report scope can no longer be widened on update
- Notification destination reads redact webhook URLs, tokens, and signing secrets across both REST and GraphQL
- Inbound webhooks bind the scan to the authenticated source, so a request body can no longer redirect a scan to another source
- Container-registry connection tests (ECR, ACR, GCR) validate the target URL, closing a server-side request forgery vector
- Source-connection URL validation resolves and pins the target address to prevent DNS-rebinding between check and use
- Webhook replay protection is now unconditional for GitHub, GitLab, and Bitbucket, with a body-hash fallback when no delivery id is present
- Runner registration rejects default registration tokens, and runner auth-token comparison is constant-time
- Registry credentials are cleared from the scanner environment after each container job
- Email changes require a second factor (password or one-time code) for single-sign-on accounts
- Repository-clone cleanup and SBOM download harden against path traversal
- CSV and report exports sanitize spreadsheet formula-injection prefixes in scanner-supplied fields
- GraphQL list arguments are validated against explicit bounds instead of silently clamping

### Fixed

- Database migrations are serialized across worker processes, preventing a startup race on a fresh database
- Correlation chains now accumulate cross-repository and credential-reuse edges discovered after the chain is first created
- Code-scanning ingestion honors the disabled-rule guard, so disabling a rule no longer marks its open findings fixed
- KEV exposure summary counts all matching findings instead of a truncated subset
- OSV matching normalizes PyPI package names, skips commit-range (GIT) advisories, and orders pre-release versions before their release
- GitLab push webhooks tolerate malformed commit payloads instead of failing the delivery
- Duplicate job-completion callbacks are idempotent and no longer re-run ingestion
- Compliance findings-for-control lists sort by severity risk order

---

## v2.5.0 — 2026-07-05

### Added

- **Agent scanner (6th scanner)** — detects AI-agent-targeted attacks in repositories: unicode bidirectional overrides, config-key injection, skill-bundle hijacking, LLM-judge poisoning, encoded payloads, homoglyphs, exfil instructions, and auto-exec configs; pure-Python detection (no external binary); enabled by default; configurable per source
- **Agent scanner compliance mapping** — agent-scanning findings mapped to compliance controls
- **Frontier escalation tier** in all four LLM verifiers (SAST, IaC, deps, agent) — dormant unless `LLM_ESCALATION_MODEL` is set; fires only on schema-validation failure in the primary chain, recall-safe
- **Eval harness** extended to SAST and IaC verifiers — measures TP/FP rates against labelled fixtures
- **SAST verifier split** into independent TP-reasoning and FP-detection chains for cleaner prompt separation
- **Base-image recommendation** for container findings — opt-in; rescans known-good base-image candidates and surfaces the provably safer tag
- **Base-layer vulnerability concentration** surfaced on container findings — shows which CVEs come from the base layer vs. the application layer
- **Opt-in newer-base-image-tag recommendation** alongside the rescan-based recommendation
- **Argus add-on card** brand mark and deduped header in settings

### Fixed

- Require re-auth before changing email or removing two-factor auth
- Carry pending-MFA token in an HttpOnly cookie instead of sessionStorage
- Harden SSO JIT: case-insensitive email match; block deprovisioned logins
- Mark policy notification/action legs as coming soon (was showing unbuilt UI)
- Notification routing now matches only on fields the event actually carries
- Runner upload size enforced via presigned POST at issue time
- Gate PCI attestation template on framework being tracked
- Align CI trigger image to the layer that introduced it

---

## v2.4.0 — 2026-06-30

### Added

- **IaC scanner** — per-source scoping, diff-scoped Checkov, file-level code windows for infrastructure findings
- **Dependency reachability** — backend-orchestrated round-trip: backend matches → enqueues job → runner judges call-graph → backend ingests verdict; recall-safe (only citation-grounded `no_path` verdicts suppress a finding)
- **SBOM component version attribution** — vulnerability counts bucketed per (name, version) pair
- **SBOM tree keyboard accessibility** and blast-radius drill-down list
- **Argus OAuth connector** with locked verification preview in settings
- **CVSS vector decoded** into a readable breakdown in the Security Brief panel
- **Advisory reference URLs** folded into finding references section
- **CISA KEV remediation**, secret validity, and detector surfaced in finding drawer
- **"View in repository" deep-link** from finding code preview
- **Finding drawer reordered** into a decision-first triage story with triage headline
- **Verdict rationale** ("why / is it a false positive") surfaces existing `verification_metadata` — no extra LLM call
- **Severity context** narrated under signal chips ("how severe is this really")
- **Dev/prod dependency scope** captured for automatic triage

### Fixed

- Secret code windows captured before clone directory is removed
- SAST/IaC/secret code window resolver made prefix-robust
- SBOM diff/vuln badge clarity and accessibility (WCAG AA light mode contrast)
- SBOM loading-state subtitles and error/empty states corrected
- SBOM compare result invalidated when selectors change
- Finding age rendered through a single `FindingAge` component (no more wrapping)
- Per-source findings tab scoped to canonical asset refs
- Hydrate fat detail blob in finding detail view

### Security

- Auth audit: case-insensitive JIT email match; block deprovisioned logins on SSO sign-in
- MFA HttpOnly cookie replaces sessionStorage for the pending-MFA token
- Email and TOTP operations require re-authentication
- Runner upload size enforced via presigned POST policy at issue time

---

## v2.3.0 — 2026-06-22

### Added

- **OSV advisory mirror** with backend-native vulnerability matching for dependencies and containers (replaces runner-side advisory download)
- **CVSS v2/v3/v4 severity derivation** — shared `osv/severity.py` maps CVSS vectors to severity bands; no more "unknown" severity for deps findings
- **EPSS ingestion job** + REST surface; EPSS displayed on findings
- **KEV catalog ingestion** + finding enrichment via CISA KEV feed
- **Posture redesign** — Overview and Triage tabs with `scannerBreakdown`, `riskContributions`, `exploitabilitySummary`, and `slaPosture` resolvers
- **Posture scoring** — configurable severity weights (10:5:2:1), band multipliers (Act×2.5 / Attend×1.6 / Track×1.0), gauge bands (75/55/35)
- **SBOM search grammar** — boolean query across component names, ecosystems, CVEs, and severity for advisory triage
- **Per-source findings tab** scoped to the source's repositories
- **Secret findings per-source scoping** — secret findings are asset-scoped per source, shown inline under the Secrets group
- Source names by org; split last-sync / last-scan columns on sources list
- Cancelled scan runs surfaced in history feed
- `ScanRun` envelopes recorded for BYO SBOM imports

### Fixed

- OSV integration tests: cross-test DB contamination fixed
- 17 stale frontend test failures resolved
- Findings: readable file paths and readable secret labels
- Asset ref vocabulary aligned between registry and source connection
- Scan banner attributes repo count to the active scanner

---

## v2.2.0 — 2026-06-15

### Added

- **GitLab CI Component, Bitbucket Pipe, Azure DevOps Task, Jenkins shared library** — customer-installable CI/CD artifacts under `integrations/`
- **PR feedback providers** for GitLab, Bitbucket, Azure DevOps — sticky comments now post to all four major SCMs (GitHub was already supported)
- **"Add to CI" snippet picker** on the source detail page — shows the right snippet for the source's SCM, with copy-to-clipboard
- **Diff-scoped scanning** — semgrep, TruffleHog (git + filesystem modes), and Checkov now operate only on files in the PR diff
- **Multi-CI PR base SHA resolver** — GitLab, Bitbucket, Azure DevOps resolve the PR base SHA via their own APIs instead of silently falling back to a full-tree scan
- **Webhook event dispatch** triggers CI scans (push-to-scan pipeline)
- **Runner deep clean** — long-poll job pickup (60 s server-side hold), pooled HTTP client with keepalive, async workspace cleanup off the scan hot path
- **Reachability signal** in SAST LLM verifier context — tree-sitter call-graph verdict (reachable / unreachable / unknown) fed into the hunter prompt
- **Pydantic validation at every LLM boundary** — SAST, SCA, secrets, and correlator chains fail-open to `needs_verify` on schema drift with WARN-level logging
- Unified `/sources` page with inner tabs: Overview / Findings / Scans / CI Integration / Settings
- Setup checklist becomes an inline dashboard card (replaces onboarding wizard)
- Connectors catalog endpoint with frontend integration
- Inbound SCM webhook notification sender migrated to new notification pipeline

### Fixed

- `Finding.engine` constraint: pre-existing values backfilled before the CHECK constraint lands
- Asyncio deprecations swept; dead helpers removed from runner router
- Legacy `dataflowTrace` JSONB key stripped from existing finding rows
- Sources API hits the correct backend path
- Notification inbox ghost preview renders newest-first

---

## v2.1.0 — 2026-06-07

### Added

- **Scanner HTTP fleet** — scanner containers expose an HTTP API; backend orchestrates them over an internal network; shared client with adapters for dependencies, containers, secrets, and SAST; scanner HTTP integration test workflow
- **Outbound notification routing** — Slack, generic webhook, and SMTP email channels; delivery history UI; per-destination Test button
- **Inbound SCM webhook receivers** — GitHub, GitLab, Bitbucket; HMAC-SHA256 signed
- **Notification routing rules** — per-rule filters and destination targeting
- **Audit log system** — auto-recorded admin and mutation events; viewer page under Settings
- **Compliance framework mapping** — SOC 2 / ISO 27001 / PCI DSS controls; backend + UI
- **SBOM export** REST endpoints + CLI (CycloneDX and SPDX formats); SBOM browser and diff pages
- **Global search** across findings, chains, repos, and CVEs
- **Activity feed** — cursor-paginated event stream from durable storage
- **API key management** — issue, rotate, revoke; scoped to org
- **Runner fleet dashboard** sourced from heartbeat data
- **Aggregated `GET /api/v1/findings`** replacing per-scanner fan-out; server-side filter, sort, and pagination
- **Findings bulk export** — streaming CSV/JSONL via REST, CLI, and toolbar
- Design-system token overhaul: ~95 surfaces migrated to `var(--color-*)` tokens; 12 missing dark-mode tokens added; `--type-2xs` (10 px) registered

### Fixed

- CSRF token bound to session instead of an hour bucket
- Session cookie security hardened

---

## v2.0.0 — 2026-06-01

Complete platform rewrite. The embedded-scanner architecture is replaced by a durable event bus, a push-dispatch job queue, and a containerised scanner fleet. The backend is restructured under `backend/src/` with bounded contexts per scanner type. The frontend is migrated into `frontend/`.

### Added

- **Durable event bus** with typed scan / finding / chain event types
- **Push-dispatch job queue** (`PostgresBackedQueue`) replacing the tight-polling loop
- **Streaming finding emit** + parallel multi-org scan orchestration
- **Per-scanner incremental baseline and delta engines** (env-gated)
- **Correlation engine** + chain graph store with 5 built-in rules: intel match, reachable CVE, secret-to-resource, lifecycle, EPSS escalation
- **Attack-chain UI** (react-flow) + findings inbox
- **Standalone Python CLI** (`aegis`) for CI/CD pipelines and local developer use
- **VSCode extension** wrapping the CLI with scan-folder / scan-file context menus and a live findings tree view
- **Argus threat-intel integration** — connector, heuristic fallbacks, webhook injection into the correlation engine
- **Asset identity foundation** — schema, helpers, manual upload, and BYO import routes
- **Filter typeahead command bar** on the findings page (WAI-ARIA aligned)
- **Settings overhaul** — profile, personal access tokens, active sessions, org identity / residency, SSO panel, notification preferences
- **Runner refactor** — Redis removed; SSRF-guarded advisory download; SBOM-only scan mode; scanner binaries pinned in `backend/Dockerfile` (Syft, Grype, TruffleHog, Semgrep)
- **Real subprocess scanner adapters** replacing previous stubs: Syft, Grype (deps + containers), Semgrep (SAST), TruffleHog (secrets)
- **`/health/deep`** endpoint with 7 concurrent subsystem probes

---

## v1.0.0 — 2026-05-25

Initial production release.

- Five scanner types: dependencies (Syft + Grype), container images (Syft + Grype), SAST (Semgrep), secrets (TruffleHog), IaC baseline
- Multi-org support with team-scoped asset grants
- Finding lifecycle: open → dismissed / fixed; assignee; SLA tracking
- RBAC with role-based permission grants
- SSO (SAML/OIDC) with JIT provisioning
- Runner-based architecture with job queue and heartbeat
- Attack chain graph (react-flow) and findings inbox
- Compliance framework mapping: SOC 2 / ISO 27001 / PCI DSS
- SBOM export (CycloneDX / SPDX); SBOM browser and diff pages
- Aggregated findings API with server-side filter, sort, and pagination
- Audit log with auto-recorded mutation events
- Notification routing: Slack, webhook, SMTP
- Activity feed (cursor-paginated)
- CI/CD integration: GitHub Action, GitLab CI Component, Bitbucket Pipe, Azure DevOps Task, Jenkins shared library
- CLI (`aegis`) with `scan`, `findings`, `triage`, `comment`, `watch`, `mcp`, and `sbom diff` subcommands
