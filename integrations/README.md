# Aegis customer-installable integrations

These are CI/CD artifacts customers add to their pipelines to trigger Aegis
security scans. Each integration talks to a single backend endpoint:
`POST /api/v1/sources/{source_id}/scans/trigger`.

## Before you install

Every integration requires an Aegis API key with the `scan:trigger` scope:

1. Open your Aegis portal → **Settings → API Keys**
2. Click **Create API key**
3. Give it a name (e.g. `ci-trigger`), select **scan:trigger** scope
4. Optionally scope to specific sources (recommended for least-privilege)
5. Copy the token — it is shown ONCE

Add the token to your CI as a secret named `AEGIS_API_KEY`. Each integration's
README documents the platform-specific way to do this.

## Available integrations

| Integration | Status | Path |
|---|---|---|
| GitHub Action | v0.1 | [`github-action/`](./github-action/) |
| GitLab Component  | v0.2.5 | [`gitlab-component/`](./gitlab-component/) |
| Bitbucket Pipe    | v0.2.5 | [`bitbucket-pipe/`](./bitbucket-pipe/) |
| Azure DevOps Task | v0.2.5 | [`azure-devops-task/`](./azure-devops-task/) |
| Jenkins Library   | v0.2.5 | [`jenkins-shared-library/`](./jenkins-shared-library/) |

## What each integration does

It does **not** run scanners locally. The Aegis backend receives the trigger,
dispatches a job to its runner pool, scans, and posts a sticky PR comment with
new findings — all via the platform. Customer CI just makes one authenticated
HTTP call per push or PR event.
