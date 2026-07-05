# Aegis GitHub Action

Trigger an Aegis security scan from a GitHub Actions workflow.

## Prerequisites

1. An Aegis instance you can reach from CI
2. An Aegis API key with `scan:trigger` scope ([how to create one](../README.md#before-you-install))
3. The source you want to scan registered in Aegis (note its `source_id`)

Then add the API key as a secret in your CI:

```sh
gh secret set AEGIS_API_KEY
```

Or via **Settings → Secrets and variables → Actions** in the GitHub UI.

## Usage

```yaml
name: Security scan
on:
  pull_request:
    types: [opened, synchronize, reopened]
  push:
    branches: [main]

jobs:
  aegis:
    runs-on: ubuntu-latest
    steps:
      - uses: blu3raven-ai/aegis@v1
        with:
          aegis-url: ${{ vars.AEGIS_URL }}
          api-key: ${{ secrets.AEGIS_API_KEY }}
          source-id: ${{ vars.AEGIS_SOURCE_ID }}
          fail-on: high
```

## Inputs

| Name | Required | Default | Description |
|---|---|---|---|
| `aegis-url` | yes | — | Aegis instance URL |
| `api-key` | yes | — | API key with `scan:trigger` scope |
| `source-id` | yes | — | Aegis source identifier for this repo |
| `wait` | no | `true` | Wait for scan completion |
| `fail-on` | no | `none` | Severity gate: `none` / `low` / `medium` / `high` |
| `poll-timeout-seconds` | no | `1800` | Poll timeout when `wait=true` |

## Behaviour

- One HTTP call per CI run — no scanner binaries downloaded
- When `wait=true`, the action polls until scan completion or timeout
- On `pull_request` events, Aegis posts a sticky comment summarising new findings
- Triage, dismissal, and fix workflow happen in the Aegis portal

## Outputs

The action writes a summary table to `GITHUB_STEP_SUMMARY` when `wait=true`.
