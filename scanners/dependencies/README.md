# SCA Scanner

Docker-based SCA scanner using Syft (SBOM generation) and Grype (vulnerability detection) for code repositories.

## Features

- SBOM generation with Syft, vulnerability scanning with Grype
- Normalized JSONL output for downstream ingestion
- Concurrent repository scanning
- Secure git cloning via GIT_ASKPASS credential helper
- Lifecycle tracking (open/fixed state candidates)

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GIT_REPOS` | Yes | Comma-separated clone URLs or path to a file |
| `GIT_TOKEN` | No | Token for authenticated git clones |
| `ORG_LABEL` | No | Organisation label for output namespacing (default: `default`) |
| `CONCURRENCY` | No | Parallel scan limit (default: `4`) |
| `RUN_ID` | No | Unique run identifier (auto-generated if unset) |

## Output Layout

```
output/<org>/runs/<run-id>/raw/<org>/<repo>/syft.json
output/<org>/runs/<run-id>/raw/<org>/<repo>/grype.json
output/<org>/runs/<run-id>/raw/<org>/<repo>/head-sha.txt
output/<org>/runs/<run-id>/normalized/findings.jsonl
output/<org>/runs/<run-id>/normalized/summary.json
output/<org>/runs/<run-id>/normalized/findings-lifecycle.jsonl
```

## Usage

```bash
# Build
make build

# Run locally
docker run --rm \
  -e GIT_REPOS=https://github.com/org/repo.git \
  -e GIT_TOKEN=ghp_xxx \
  -e ORG_LABEL=my-org \
  -v $(pwd)/output:/scanner/output \
  sca-scanner:latest

# Run tests
make test
```
