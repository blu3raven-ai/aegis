# Smoke Test — Embedded Scanner Cutover

Verifies the embedded scanner produces `findings.jsonl` that is byte-equivalent
to the previous Docker-per-scan output for the same input.

## Prerequisites

- A staging environment where both versions can be deployed against the same
  PostgreSQL + MinIO backend (or two isolated stacks pointed at the same fixture)
- A small public fixture repository with stable findings — suggest a tagged
  release commit so the input never drifts
- `aws`/`mc` CLI to pull artifacts out of MinIO

## Steps

### 1. Baseline on `main`

- Check out `main` and deploy (`docker compose up -d --build`)
- From the portal, run a scan against the fixture repository
- Download `findings.jsonl` from MinIO:
  `s3://${S3_BUCKET}/<org>/<tool>/<run_id>/findings.jsonl`
- Save locally as `baseline-findings.jsonl`

### 2. New build on `refactor/embedded-scanners`

- Check out `refactor/embedded-scanners` and deploy
  (`docker compose down && docker compose up -d --build`)
- Run the **same** scan against the **same** fixture commit
- Save the output as `embedded-findings.jsonl`

### 3. Diff

```bash
python3 <<'EOF'
import json
import sys

VOLATILE_KEYS = {"scanTimestamp", "ts", "firstSeenAt", "lastSeenAt"}


def normalize(line: str) -> dict:
    record = json.loads(line)
    for key in VOLATILE_KEYS:
        record.pop(key, None)
    return record


def sort_key(record: dict) -> tuple[str, str, str]:
    return (
        record.get("finding_id", ""),
        record.get("repository", ""),
        record.get("rule_id", ""),
    )


baseline = sorted(
    (normalize(line) for line in open("baseline-findings.jsonl")),
    key=sort_key,
)
embedded = sorted(
    (normalize(line) for line in open("embedded-findings.jsonl")),
    key=sort_key,
)

if len(baseline) != len(embedded):
    print(f"COUNT DIFF: baseline={len(baseline)} embedded={len(embedded)}")
    sys.exit(1)

for index, (left, right) in enumerate(zip(baseline, embedded)):
    if left != right:
        print(f"ROW {index} DIFF:")
        print("BASELINE:", json.dumps(left, indent=2, sort_keys=True))
        print("EMBEDDED:", json.dumps(right, indent=2, sort_keys=True))
        sys.exit(1)

print("OK — outputs match")
EOF
```

## Acceptable differences

Strip these keys before diffing (they vary per scan):

- `scanTimestamp`, `ts`, `firstSeenAt`, `lastSeenAt`
- Any per-finding internal IDs that embed `run_id`

## Known candidates for divergence

All three scan modes (`full`, `advisories_only`, `sbom_only`) are now ported.
The following are areas where output may legitimately differ and need manual
verification before concluding there is a regression:

- `manifestSnippet` field ordering in SBOM registrations — Python dict ordering
  vs bash jq output may differ; normalise before diffing.
- `normalize` output field shape if the bundled grype binary version differs
  from the bash baseline grype version — check `grype version` on both.
- Empty vs absent `findings.jsonl` in `sbom_only` mode — verify which shape the
  backend expects when no findings are generated.
- ONNX classifier cold-start latency on the first secrets scan is higher than
  the bash baseline, but findings should be identical once the model is loaded.
