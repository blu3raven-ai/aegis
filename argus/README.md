# Argus

Standalone verification service for Aegis findings. Hosts the LLM
hunter/skeptic/critic verification loop (copied from the runner) behind an HTTP
seam so the runner can call it as a thin, stateless client instead of running
the agent loop in-process.

## Layout

- `verification/` — the verification "brain" (copied from `runner/verification`,
  imports rewritten to `argus.verification.*`).
- `models.py` — request/response models for `/v1/verify`.
- `service.py` — FastAPI app: `GET /health`, `POST /v1/verify`.
- `client.py` — `ArgusClient`, the Aegis-side thin client.

## How it works

The verifiers read code from a filesystem `repo_root`. The service materializes
each finding's shipped `code_context.files` into a temp dir (jailed against
`..` traversal) and passes that as `repo_root`, so the copied verification code
runs unchanged. Per-finding errors fail open to a `needs_verify` result rather
than failing the whole batch.

## Run

```bash
pip install -r argus/requirements.txt

LLM_API_KEY=sk-... \
LLM_API_BASE_URL=https://api.openai.com/v1 \
LLM_API_MODEL=gpt-4o-mini \
uvicorn argus.service:app --port 8787
```

`ARGUS_TOKEN` is optional; if set, `/v1/verify` requires a matching bearer.

## Example

```bash
curl -s localhost:8787/health
# {"status":"ok"}

curl -s -X POST localhost:8787/v1/verify \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "scan-1",
    "scanner": "code_scanning",
    "findings": [{
      "finding_id": "f1",
      "detail": {"file": "a.py", "line": 1, "tool": "sast", "rule": "x", "severity": "high"},
      "code_context": {"files": [{"path": "a.py", "content": "x = get_input()\nsink(x)\n"}]}
    }]
  }'
```

## Test

```bash
python -m pytest argus/tests/ -q
```
