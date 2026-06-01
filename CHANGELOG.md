# Changelog

## [Unreleased]

### Added — Correlation, intel, and detection

- **Phase 11:** temporal correlation foundation — spec §5.6 Type 4 (PR #42)
- **Phase 30:** Argus connector hardening — circuit breaker, retries, metrics, pooled client (PR #70)
- **Phase 48:** CISA KEV catalog ingestion + finding enrichment (PR #79)
- **Phase 50:** EPSS ingestion job + REST surface (PR #82)
- **Phase 54:** EPSS surfaced in findings list and dashboard (PR #83)
- **SAST v1.1:** cross-file one-hop taint expansion for delta scans (PR #34)
- **Finding attribution:** commit/PR attribution as derived fields per spec §5.6 (PR #35)

### Added — Notifications, audit, and compliance

- **Phase 13:** outbound notification routing — Slack, generic webhook, SMTP email (PR #44)
- **Phase 13 (UI):** notification destinations settings page with delivery history (PR #50)
- **Phase 14:** inbound SCM webhook receivers for GitHub, GitLab, Bitbucket (PR #41)
- **Phase 19:** audit log system with auto-recorded admin/mutation events (PR #47)
- **Phase 19 (UI):** audit log viewer page under settings (PR #55)
- **Phase 29:** compliance framework mapping — SOC 2 / ISO 27001 / PCI DSS controls, backend + UI (PR #63)
- **Phase 42:** notification routing rules — per-rule filters and destination targeting (c3a5473)
- **Phase 44:** HMAC-SHA256 outbound webhook signing (PR #75)
- **Phase 47:** per-severity SLA tracking with breach dashboard (PR #76)
- **Webhook receiver SDKs:** Python and Node.js helpers for downstream consumers (PR #78)
- **Notifications test-send:** per-destination Test button + backend endpoint with canned payload, no delivery-record persistence (PR #106)

### Added — Operator surfaces and dashboards

- **Phase 17 (UI):** Insights dashboard exposing temporal correlation APIs (PR #45)
- **Phase 18:** SBOM export REST endpoints + CLI (CycloneDX/SPDX) (PR #48)
- **Phase 18 (UI):** SBOM browser page (PR #52)
- **Phase 25:** API key management — issue, rotate, revoke (PR #66)
- **Phase 27:** repos asset management page surfacing monitored repos (PR #56)
- **Phase 28:** global search across findings, chains, repos, CVEs (PR #57)
- **Phase 33:** `/health/deep` endpoint with 7 concurrent subsystem probes (PR #64)
- **Phase 37:** `aegis sbom diff` — added/removed/changed components between SBOM versions (PR #67)
- **Phase 40:** runner fleet dashboard sourced from Redis heartbeat hash (PR #68)
- **Phase 43 (UI):** SBOM diff page (PR #72)
- **Phase 52:** activity feed — cursor-paginated event stream from durable storage (PR #80)
- **Phase 55:** aggregated `GET /api/v1/findings` endpoint replacing per-scanner fan-out (PR #85)
- **Findings page:** wired to the aggregated endpoint for server-side filter/sort/page (PR #93)
- **Findings bulk export:** streaming CSV/JSONL REST + CLI + toolbar button (PR #77)
- **Onboarding wizard:** stateful onboarding service backed by `app_config` (f1462ad)

### Added — CLI, VSCode, and integrations

- **Phase 5c (VSCode):** chain graph webview, quick-fix code actions, tree view grouping (PR #46)
- **Phase 15:** `aegis report` CLI command + runner Prometheus metrics (PR #43)
- **Phase 34:** `aegis comment` CLI subcommand (PR #60)
- **Phase 36:** `aegis init` CLI subcommand (PR #62)
- **Phase 39 (VSCode):** scan-folder / scan-file context menus + rescan-with-latest-rules (PR #65)
- **Phase 41:** `aegis triage` CLI subcommand (PR #69)
- **Phase 46:** CLI shell completion + interactive triage shell (PR #74)
- **Phase 53:** `aegis watch` CLI subcommand built on the SSE event bus (PR #81)
- **Phase 56 (CLI):** `aegis findings` consumes the aggregated endpoint server-side (PR #86)
- **Phase 56 (VSCode):** live findings tree view mirroring `aegis watch` (PR #87)
- **CLI report/triage/comment:** migrated to aggregated `/api/v1/findings` endpoint (PR #100)
- **Attribution UI + `aegis login`:** finding-drawer attribution + CLI auth flow (PR #36)
- **MCP server:** `aegis mcp` subcommand exposing Aegis to AI agents (cd54bae)
- **`/api/v1/decisions/go-no-go` endpoint:** server-side heuristic with per-org isolation; CLI falls back locally only on 404/405 (PR #107)

### Added — Phase 7 scanner HTTP rollout

- **Phase 7 (steps 1–2):** scanner HTTP API foundation + shared client (PR #96)
- **Phase 7 (steps 3–5):** dependencies + container adapters switched to HTTP (PR #97)
- **Phase 7 (steps 6–7):** secrets + SAST adapters switched to HTTP — TruffleHog + OpenGrep (PR #98)
- **Phase 7 (steps 8–9):** scanner HTTP integration test workflow + docs (PR #101)
- **Phase 7 refactor:** shared `scanners/shared/http_api_base.py` + `backend/src/shared/checkout_upload.py` consolidating 4-way duplication; -109 LOC net (PR #102)
- **CI integration test resilience:** skip secrets scanner build (pending lighter image) + repair cdxgen binary copy in deps Dockerfile (PR #105)
- **Phase 1b warm scanner pool wired:** `WarmPoolManager` started from `runner/agent.py` lifecycle gated by `AEGIS_WARM_POOL_ENABLED=true` (default off); backward-compatible with existing `RUNNER_EXEC_MODE=warm_pool` (PR #115)

### Changed

- **Sidebar reorganization:** grouped into Overview / Sources / Analytics / Operations (PR #73)
- **Sidebar compact:** trimmed 19 nav items to 16 (PR #92)
- **Sidebar consolidation (Strategy B):** further consolidated to 12 items (PR #94)
- **Phase 20:** scanner and backend Dockerfile hardening — multi-stage, non-root, pinned base, HEALTHCHECK (PR #49)
- **UI impeccable audit:** systematic UI/UX cleanup across the app (PR #40)
- **Scan running banner:** quieter rewrite (PR #91)
- **Nav active states:** removed `border-l-2` stripe (PR #90)
- **`rule_pack_version` removed from scanner SAST HTTP API:** phantom field never used or forwarded (PR #108)
- **Impeccable polish on recently-shipped surfaces:** token alignment, gradient/blue-class removal, dark-mode parity (PR #109)
- **Drawer heading aligned:** finding drawer attribution row now renders "Introduced by" matching internal-doc spec (PR #113)
- **Polish round 2:** 36 token alignments across 11 surfaces — per-scanner dashboards, /chains, /compliance, /sbom/[repoId], settings sub-pages (account/users/organisations/api-keys/license) (PR #116)
- **Design-system token round (Argus, state-pending, overlay, type-2xs):** added 12 missing dark-mode tokens for `--color-verdict-*` and `--color-state-*` subtle/border variants, plus new families: `--color-argus*` (light/dark argus brand), `--color-state-pending*` (amber warn), `--color-overlay` / `--color-overlay-strong` (modal masks), `--color-accent-border`, `--color-status-ok-subtle`/`-border`, `--color-severity-*-subtle`/`-border` for all four severity tiers, `--color-state-fixed-border` / `--color-state-deferred-border`, `--type-2xs` (10px) (PR #119, PR #121)
- **Token migration across ~95 surfaces:** replaced hardcoded Tailwind color literals (`bg-purple-500`, `text-red-400`, `bg-amber-100`, etc.) with `var(--color-*)` tokens across argus surfaces (PR #122), settings forms (PR #123), layout + auth + notifications (PR #124), secrets dashboards (PR #125), dependencies/code/containers dashboards (PR #126), settings content + role/org (PR #127), settings sources + runners (PR #128), shared/compliance/fleet/notifications (PR #129), and final stragglers (PR #130) — including dropping ad-hoc `dark:` overrides where tokens auto-resolve both modes
- **Charts migrated to severity tokens:** secrets analytics charts (org-age-buckets, secret-type, backlog-health, org-secret-heatmap) use `var(--color-severity-*)` instead of literal hex (PR #120)
- **Misc design-drift fixes:** ConnectionStatusBadge error color uses `--color-severity-critical`; overview-attention-strip drops decorative `to-cyan-400` gradient for solid accent bar; code scanning dashboard bulk-actions toolbar + reopen button use accent tokens (PR #121)
- **CI:** alembic single-head workflow gains `workflow_dispatch` trigger so it can be re-run manually without backend/alembic changes (PR #118)
- **Modal overlay tokens applied:** every `bg-black/X` backdrop across 12 dialogs/drawers/modals migrated to `--color-overlay` / `--color-overlay-strong` — light mode gets a navy-tinted overlay, dark mode a darker black, removing inverted-contrast cases (PR #132)
- **Leftover Tailwind literals swept:** setup forms (dependencies + containers) amber warning/required-field/validation chrome and red error banners; dependencies dashboards patch-version text; ScanHealthTable failed-status row + text; SbomExplorer error banner + "found in estate" indicator — all now use state-pending / severity-critical / state-fixed tokens; `ECOSYSTEM_COLORS` chips intentionally kept as categorical (PR #132)

### Added — Operator tooling and tests

- **CI workflow templates:** `examples/ci/` templates for downstream `aegis scan` integration (PR #53)
- **E2E coverage:** expanded Playwright coverage for Findings, Chains, Insights, Notifications, Audit, CLI, health (PR #51)
- **CI:** assert single Alembic head on backend changes (PR #88)
- **CLI test refactor:** cursor walker shim replaced with direct iter_all_findings mocks (-178 LOC) (PR #114)

### Fixed

- Redis service missing from `docker-compose.yml` — closes v1 deploy gap (PR #95)
- Pre-existing backend test failures triaged; linearize Alembic heads (SLA / webhook / KEV) into a single chain (PR #84)
- `prerequisite_utils` test failures (PR #37)

## [v1.1.0] - 2026-05-31

### Added — Phase 9: warm pool full activation + real scanner adapters

- **Daemon-mode entrypoint for all 4 scanner images** (`scanners/{dependencies,container,code-scanning,secrets}/daemon_entry.py`): when `RUNNER_EXEC_MODE=daemon`, the container loops on its Redis input stream (XREADGROUP), invokes the existing `run.sh` per job, publishes a `WarmResultMessage` to the result stream, and XACKs. Per-job mode (default) execvs `run.sh` unchanged — no behaviour change for existing deployments.
- **Result stream consumer in `runner/agent.py`**: when `RUNNER_EXEC_MODE=warm_pool`, `RunnerAgent.start()` spawns a background thread per scanner type that subscribes to `aegis.scanner.results.<type>`, calls `_report_completion` / `_report_failure` based on `WarmResultMessage.status`, and XACKs.
- **Real subprocess adapters** replacing Phase 7 `NotImplementedError` stubs:
  - `backend/src/dependencies/syft_adapter.py` — `syft <path> -o cyclonedx-json`
  - `backend/src/dependencies/grype_adapter.py` — `grype sbom:<path> -o json`
  - `backend/src/containers/syft_adapter.py` — `syft registry:<image_ref> -o cyclonedx-json`
  - `backend/src/containers/grype_adapter.py` — mirrors deps grype adapter
  - `backend/src/code_scanning/opengrep_adapter.py` — `opengrep --config=auto --json`
  - `backend/src/secrets/trufflehog_adapter.py` — `trufflehog git file://... --since-commit --json`
- **Shared subprocess helper** (`backend/src/shared/subprocess_runner.py`): `AdapterUnavailableError` (binary absent from PATH) and `AdapterFailedError` (non-zero exit) give operators actionable error messages. Incremental engine callers catch all exceptions and fall through to full-scan as before.
- **Scanner binary installs in `backend/Dockerfile`**: Syft v1.24.0, Grype v0.92.0, TruffleHog v3.95.2, Opengrep v1.20.0 (all pinned; override via ARG in CI).
- **`redis-py` install in all 4 scanner Dockerfiles** for daemon-mode stream IPC.
- **125 new tests** (31 runner + 29 adapter + shared helper); all mocked — no real binaries required in CI.

## [v1.0.0] - 2026-05-31

### Added — Near-real-time scanner redesign

- **Phase 0:** Durable Redis Streams event bus + event types + cache schema (Alembic migration `876f112b2034`)
- **Phase 1a:** Push-dispatch job queue — PostgresBackedQueue + RedisBackedQueue + pub/sub notifications + runner subscription mode (env-gated)
- **Phase 1b:** Warm scanner pool foundation (WarmPool + dispatcher; production rollout pending scanner Dockerfile daemon mode)
- **Phase 1c:** Streaming finding emit + parallel multi-org orchestration (default 8 concurrent orgs)
- **Phase 2a-d:** Per-scanner baseline+delta incremental engines (dependencies / containers / SAST / secrets), opt-in via `AEGIS_USE_INCREMENTAL_*` env flags
- **Phase 3a:** Correlation engine + chain graph store + 5 built-in rules (intel match, reachable CVE, secret-to-resource, lifecycle, EPSS escalation)
- **Phase 3b:** UI chain view + findings inbox + chain visualization via react-flow
- **Phase 4:** Argus first-class integration (connector + heuristic fallbacks + webhook + correlation engine injection)
- **Phase 5a:** Standalone Python CLI (`aegis` command) for CI/CD pipeline + local developer use
- **Phase 5b:** VSCode extension wrapping the CLI
- **Phase 6:** Production wiring — correlation engine startup hook + `/health` endpoint + deployment README
- **Phase 7:** Wired Phase 2 incremental engines into live scanner ingest paths (env-gated; adapters are stubs pending scanner-container API)

### Fixed

- 8 pre-existing test failures in `test_event_bus` / `test_runner_sse_publish` / `test_graphql_security`
  - `test_event_bus` / `test_runner_sse_publish` (7 failures): `EventBus.subscribe()` was refactored to return `(sub_obj, generator)` to allow callers to mutate subscriber state without reconnecting; tests were using the old single-return API
  - `test_graphql_security` (1 failure): `clamp_per_page` had no upper bound, allowing arbitrarily large page sizes — fixed production code to cap at 100
- Dependabot vulnerabilities (3):
  - `postcss` < 8.5.10 (npm, medium) — XSS via unescaped `</style>` in CSS Stringify output; forced to 8.5.15 via `overrides`
  - `idna` < 3.15 (pip, medium) — specially crafted input can bypass the CVE-2024-3651 fix; upgraded to 3.17
  - `Mako` <= 1.3.11 (pip, high) — path traversal via backslash URI on Windows in TemplateLookup; upgraded to 1.3.12

### Notes

- Default config preserves all pre-v1 behavior. Every new feature is gated by an env flag.
- See README "Production Configuration" for the rollout path.
- Internal architecture docs intentionally not in this repo — they live in the engineering workspace.
