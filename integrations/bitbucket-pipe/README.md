# Aegis Bitbucket Pipe

Trigger an Aegis security scan from a Bitbucket Pipelines step.

## Prerequisites

1. An Aegis instance you can reach from CI
2. An Aegis API key with `scan:trigger` scope ([how to create one](../README.md#before-you-install))
3. The source you want to scan registered in Aegis (note its `source_id`)

Then add the API key as a secret in your CI:

**Repository Settings → Pipelines → Repository variables** → add `AEGIS_API_KEY` (secured).

## Usage

In your repo's `bitbucket-pipelines.yml`:

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: Aegis security scan
          script:
            - pipe: docker://blu3raven-ai/aegis-pipe:v1
              variables:
                AEGIS_URL: $AEGIS_URL
                AEGIS_API_KEY: $AEGIS_API_KEY
                SOURCE_ID: $AEGIS_SOURCE_ID
                FAIL_ON: high
  branches:
    main:
      - step:
          name: Aegis security scan
          script:
            - pipe: docker://blu3raven-ai/aegis-pipe:v1
              variables:
                AEGIS_URL: $AEGIS_URL
                AEGIS_API_KEY: $AEGIS_API_KEY
                SOURCE_ID: $AEGIS_SOURCE_ID
                FAIL_ON: high
```

Configure `AEGIS_URL`, `AEGIS_API_KEY` (secured), and `AEGIS_SOURCE_ID` under **Repository settings → Repository variables** (or workspace variables for org-wide use).

## Variables

| Name | Required | Default | Description |
|---|---|---|---|
| `AEGIS_URL` | yes | — | Aegis instance URL |
| `AEGIS_API_KEY` | yes | — | API key with `scan:trigger` scope (use a secured variable) |
| `SOURCE_ID` | yes | — | Aegis source identifier for this repo |
| `WAIT` | no | `"true"` | Wait for scan completion |
| `FAIL_ON` | no | `"none"` | Severity gate: `none` / `low` / `medium` / `high` |
| `POLL_TIMEOUT_SECONDS` | no | `"1800"` | Poll timeout when `WAIT=true` |

## Building the image

This pipe is published as `blu3raven-ai/aegis-pipe:v1` on Docker Hub. To build locally:

```sh
docker build -t aegis-pipe:dev .
```

## Behaviour

- One HTTP call per pipeline step — no scanner binaries downloaded
- When `WAIT=true`, polls until completion or timeout, then prints a summary to the step log
- On PR pipelines, Aegis posts a sticky PR comment summarising new findings
