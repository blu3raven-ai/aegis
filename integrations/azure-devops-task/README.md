# Aegis Azure DevOps Task

Trigger an Aegis security scan from an Azure Pipelines job.

## Prerequisites

1. An Aegis instance you can reach from CI
2. An Aegis API key with `scan:trigger` scope ([how to create one](../README.md#before-you-install))
3. The source you want to scan registered in Aegis (note its `source_id`)

Then add the API key as a secret in your CI:

**Pipelines → Library → Variable groups** → add `AEGIS_API_KEY` (secret).

## Install

```sh
cd task
npm install
npm run build
```

Package the extension with [`tfx-cli`](https://www.npmjs.com/package/tfx-cli):

```sh
npm install -g tfx-cli
tfx extension create --manifest-globs vss-extension.json
```

Upload the resulting `.vsix` to the Visual Studio Marketplace (or to your private publisher) and install it into your Azure DevOps organization.

## Usage

In your pipeline YAML:

```yaml
trigger:
  branches:
    include: [main]
pr:
  branches:
    include: ['*']

steps:
  - task: AegisScan@1
    inputs:
      aegis-url: $(AEGIS_URL)
      aegis-api-key: $(AEGIS_API_KEY)
      source-id: $(AEGIS_SOURCE_ID)
      fail-on: high
```

Define `AEGIS_URL`, `AEGIS_API_KEY` (secret), and `AEGIS_SOURCE_ID` as pipeline variables or in a variable group.

## Inputs

| Name | Required | Default | Description |
|---|---|---|---|
| `aegis-url` | yes | — | Aegis instance URL |
| `aegis-api-key` | yes | — | API key with `scan:trigger` scope (reference a secret variable) |
| `source-id` | yes | — | Aegis source identifier for this repo |
| `wait` | no | `true` | Wait for scan completion |
| `fail-on` | no | `none` | Severity gate: `none` / `low` / `medium` / `high` |
| `poll-timeout-seconds` | no | `1800` | Poll timeout when `wait=true` |

## Behaviour

- One HTTP call per pipeline run — no scanner binaries downloaded
- When `wait=true`, polls until completion or timeout, then attaches a markdown summary to the build
- On PR pipelines, Aegis posts a sticky PR comment summarising new findings
- `cancelled` status is reported as a warning (not a failure) — Azure cancels older runs when newer commits arrive
