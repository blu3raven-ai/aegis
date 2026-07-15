# Runner

Long-running scanner agent that picks jobs off the backend queue, runs the
embedded vulnerability scanners against user repos / container images / IaC,
and uploads results back via presigned URLs. Runs as a single Python process;
zero S3 credentials, BYO-LLM for verification.

## Package layout

```
runner/
  agent.py                  main service loop + CLI entry (`vuln-runner` script)

  core/                     runtime infrastructure
    dispatcher.py             job type → scanner instance routing
    graceful_drain.py         drain-on-SIGTERM lifecycle

  clients/                  external IO
    backend.py                HTTP client for backend presign + status endpoints
    uploader.py               presigned multipart POST helper (size-capped, with retry)
    streamer.py               streams scan output to MinIO via the uploader

  observability/            metrics + structured logging
    metrics.py                psutil resource probes + Prometheus counters
    logging.py                JSON-structured logging configuration

  scanners/                 embedded scan implementations
    dependencies/             SBOM via syft + cdxgen (matched backend-side against the OSV mirror)
    code_scanning/            SAST via semgrep + tree-sitter reachability
    secrets/                  TruffleHog + LLM-verified secret findings
    container/                container image vulnerability scanning
    iac/                      Infrastructure-as-Code (checkov) scanning

  verification/             agentic verification ecosystem (BYO-LLM)
    core/                     llm_client, budget enforcement
    schemas/                  pydantic data contracts (Evidence, Verdict)
    prompts/                  per-role prompt library (sast / secrets / sca / correlator)
    verifiers/                per-scanner verify_<type>_finding orchestrations
    helpers/                  pure utilities (import_sites)
    agents/                   tool-using investigator loop
    tools/                    grep_repo, read_file_range, fetch_advisory
    pipelines/                multi-scanner correlator, orchestrator, dedupe
    critic.py                 mechanical citation verifier
```

## Service entry point

`agent.py` owns both the runtime and its CLI surface:

* `RunnerAgent` — the main service. Heartbeat thread, job poll loop, per-job
  worker pool, drain handling. Imports the dispatcher to route jobs to the
  right scanner.
* `cli` — Click command group with `configure` (register with the portal) and
  `start` (run the agent). Pinned by `pyproject.toml` as the `vuln-runner`
  script.

## Running locally

```sh
# install
pip install -e .

# run as a foreground service
vuln-runner

# verbose JSON logging to stdout
RUNNER_LOG_FORMAT=json vuln-runner
```

Required environment for normal operation:

| Variable | Purpose |
|---|---|
| `RUNNER_BACKEND_URL` | Base URL of the backend `/api/v1/agent/*` endpoints |
| `RUNNER_AUTH_TOKEN` | Bearer token issued by the backend for this runner |
| `RUNNER_WORKSPACE` | Local scratch directory for per-job work (default `/workspace`) |
| `RUNNER_METRICS_PORT` | Optional Prometheus scrape port (skipped if unset) |

Optional LLM verification (paid-tier capability — scans succeed without it):

| Variable | Purpose |
|---|---|
| `LLM_API_KEY` | BYO key for any OpenAI-compatible endpoint |
| `LLM_API_BASE_URL` | Defaults to `https://api.openai.com/v1` |
| `LLM_API_MODEL` | Defaults to `gpt-4o-mini` |
| `LLM_TOKEN_BUDGET_PER_SCAN` | SAST per-scan budget (default 200k) |
| `LLM_TOKEN_BUDGET_PER_SCAN_SCA` | SCA per-scan budget (default 100k) |
| `LLM_TOKEN_BUDGET_PER_SCAN_SECRETS` | Secrets per-scan budget (default 150k) |
| `LLM_DAILY_REMAINING` | Org-wide daily cap (default 1M) |

## Verification ecosystem

Findings flow:

```
scanner output (jsonl)
        │
        ▼
 per-scanner verifier      ─── Hunter → Skeptic → mechanical Critic
        │                      verdict + evidence + cited file:line
        ▼
 orchestrator              ─── triages: deep / standard / deferred
        │                      splits budget between deep verify + correlator
        ▼
 cross-scanner correlator  ─── investigator agent (grep + read + fetch_advisory)
        │                      surfaces real attack chains spanning scanners
        ▼
 deduplication             ─── collapses logically-equivalent findings,
        │                      preserves every source location as evidence
        ▼
 final findings.jsonl      ─── verdict-stamped, evidence-rich, deduplicated
```

The mechanical critic at every verifier gate enforces citation grounding: any
file:line evidence the LLM emits must survive a grep against the actual repo,
or the verdict is demoted from `confirmed` to `needs_verify`. Advisory
citations require a `source` (CVE / GHSA id) and a `snippet` (verbatim quote).

## Smoke-testing scanner output

To verify scanner output stability after changes, diff `findings.jsonl` against
a known-good baseline run on the same fixture commit. Strip these volatile
keys before comparison:

- `scanTimestamp`, `ts`, `firstSeenAt`, `lastSeenAt`
- Internal IDs that embed `run_id`

Per-scanner test suites under `tests/runner/scanners/` already cover
normalize + verify behavior with stub LLMs and fixture inputs.

## Adding a new scanner

1. Add a subpackage under `runner/scanners/<name>/` with at minimum a
   `scanner.py` exposing a class with `run_scan(job, job_dir, on_progress, cancel_event)`.
2. Register the type → class mapping in `runner/core/dispatcher.py`.
3. Add tests in `tests/runner/scanners/test_<name>.py`.
4. If the scanner should support LLM verification, add a verifier under
   `runner/verification/verifiers/<name>.py` and prompts under
   `runner/verification/prompts/<name>.py`, then wire it from the scanner's
   `_verify_findings_file()` hook.
