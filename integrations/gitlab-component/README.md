# Aegis GitLab CI/CD Component

Trigger an Aegis security scan from a GitLab CI pipeline.

## Prerequisites

1. An Aegis instance you can reach from CI
2. An Aegis API key with `scan:trigger` scope ([how to create one](../README.md#before-you-install))
3. The source you want to scan registered in Aegis (note its `source_id`)

Then add the API key as a secret in your CI:

Project **Settings → CI/CD → Variables** → add `AEGIS_API_KEY` (masked + protected).

## Usage

In your project's `.gitlab-ci.yml`:

```yaml
include:
  - component: gitlab.com/blu3raven-ai/aegis/gitlab-component@v1
    inputs:
      aegis_url: $AEGIS_URL
      aegis_api_key: $AEGIS_API_KEY
      source_id: $AEGIS_SOURCE_ID
      fail_on: high
```

Define `AEGIS_URL`, `AEGIS_API_KEY` (masked + protected), and `AEGIS_SOURCE_ID` as CI/CD variables under **Settings → CI/CD → Variables**.

## Inputs

| Name | Required | Default | Description |
|---|---|---|---|
| `aegis_url` | yes | — | Aegis instance URL |
| `aegis_api_key` | yes | — | API key with `scan:trigger` scope (use a masked CI/CD variable) |
| `source_id` | yes | — | Aegis source identifier for this repo |
| `wait` | no | `true` | Wait for scan completion |
| `fail_on` | no | `none` | Severity gate: `none` / `low` / `medium` / `high` |
| `poll_timeout_seconds` | no | `1800` | Poll timeout when `wait=true` |

## Behaviour

- One HTTP call per pipeline — no scanner binaries downloaded
- Runs on `alpine:3.20` with `bash`, `curl`, `jq` installed
- Triggers on merge-request pipelines and default-branch pushes
- When `wait=true`, polls until completion or timeout, then writes a summary to the job log
- On MR pipelines, Aegis posts a sticky MR comment summarising new findings

## Maintenance

### Script sync requirement

The runtime logic lives **inlined** in `templates/aegis-scan.yml` under the `script:` block. The `scripts/trigger.sh` file is kept as a developer-readable source-of-truth. **The two MUST stay in sync** — any change to the bash logic requires updating both files.

To verify sync:

```bash
diff <(sed -n '/AEGIS_SCAN_END/,/AEGIS_SCAN_END/p' templates/aegis-scan.yml | sed '1d;$d') scripts/trigger.sh
```

(Identical output expected. Build automation that inlines on release is a v0.3 follow-up.)
