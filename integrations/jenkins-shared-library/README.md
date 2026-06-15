# Aegis Jenkins Shared Library

Trigger an Aegis security scan from a Jenkins pipeline via a `@Library`-imported DSL step.

## Prerequisites

1. An Aegis instance you can reach from CI
2. An Aegis API key with `scan:trigger` scope ([how to create one](../README.md#before-you-install))
3. The source you want to scan registered in Aegis (note its `source_id`)

Then add the API key as a secret in your CI:

**Manage Jenkins → Credentials** → add a Secret text credential named `AEGIS_API_KEY`.

## Jenkins library configuration

Because this library lives under `integrations/jenkins-shared-library/` in the
main Aegis repository, Jenkins needs to know where to find it. In **Manage
Jenkins → System → Global Pipeline Libraries**, add:

| Field | Value |
|---|---|
| Name | `aegis-shared-library` |
| Default version | `main` (or a release tag like `v1`) |
| Library Path | `integrations/jenkins-shared-library` |
| Retrieval method | Modern SCM → Git |
| Project Repository | `https://github.com/blu3raven-ai/aegis.git` |

The `Library Path` setting tells Jenkins to look for `vars/` and `src/`
relative to that path instead of the repo root.

## Install

1. In Jenkins, go to **Manage Jenkins → System → Global Pipeline Libraries**.
2. Add a new library:
   - Name: `aegis-shared-library`
   - Default version: `v1` (or a specific tag)
   - Retrieval method: **Modern SCM** → Git
   - Project repository: `https://github.com/blu3raven-ai/aegis.git`
   - Library path hint: this library lives under `integrations/jenkins-shared-library/` in the repo — set the SCM checkout path accordingly, or fork the subtree into its own repo.
3. (Recommended) Tick **Load implicitly** off and let each Jenkinsfile opt in explicitly.

No extra Jenkins plugins are required beyond the standard Pipeline plugin.

## Usage

In your `Jenkinsfile`:

```groovy
@Library('aegis-shared-library@v1') _

pipeline {
    agent any
    stages {
        stage('Security scan') {
            steps {
                aegisScan(
                    aegisUrl: env.AEGIS_URL,
                    apiKey: env.AEGIS_API_KEY,
                    sourceId: env.AEGIS_SOURCE_ID,
                    failOn: 'high'
                )
            }
        }
    }
}
```

Store `AEGIS_API_KEY` as a Jenkins credential and inject it via `withCredentials` or the global env, not a literal.

## Parameters

| Name | Required | Default | Description |
|---|---|---|---|
| `aegisUrl` | yes | — | Aegis instance URL |
| `apiKey` | yes | — | API key with `scan:trigger` scope |
| `sourceId` | yes | — | Aegis source identifier for this repo |
| `wait` | no | `true` | Wait for scan completion |
| `failOn` | no | `'none'` | Severity gate: `none` / `low` / `medium` / `high` |
| `pollTimeoutSeconds` | no | `1800` | Poll timeout when `wait=true` |

## Behaviour

- Reads `env.GIT_COMMIT`, `env.GIT_BRANCH` (strips `origin/` prefix), `env.CHANGE_ID` (PR builds), `env.BUILD_NUMBER`
- One HTTP call per pipeline run — no scanner binaries downloaded
- When `wait=true`, polls until completion or timeout, then logs a summary
- On multi-branch PR builds, Aegis posts a sticky PR comment summarising new findings
- HTTP transport uses standard `java.net.HttpURLConnection` — no `httpRequest` plugin needed
