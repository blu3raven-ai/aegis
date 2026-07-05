# Aegis CI/CD integration examples

Drop-in workflows for the major CI/CD platforms. Pick your platform, copy the template, set the secrets, and Aegis runs on every PR and push.

## Quick start

1. Generate an API token at `/settings/api-keys` in the Aegis UI.
2. Add the token to your CI platform's secrets as `AEGIS_API_TOKEN`.
3. Add your Aegis backend URL as `AEGIS_BASE_URL`.
4. Copy one of the templates from this directory into your repository.
5. Adjust scanner types and block-on policy as needed.

## Templates

| Platform | Directory |
|---|---|
| **GitHub Actions** | `github-actions/` |
| **GitLab CI** | `gitlab-ci/` |
| **Jenkins** | `jenkins/` |
| **CircleCI** | `circleci/` |
| **Azure Pipelines** | `azure-pipelines/` |
| **Buildkite** | `buildkite/` |

## GitHub Actions

Copy `github-actions/aegis-scan.yml` to `.github/workflows/` in your repository.
Use `aegis-pr-gate.yml` to gate pull requests, or drop `action.yml` into a
`.github/actions/aegis/` directory and reference it as a composite action:

```yaml
- uses: ./.github/actions/aegis
  with:
    aegis-api-token: ${{ secrets.AEGIS_API_TOKEN }}
    aegis-base-url: ${{ secrets.AEGIS_BASE_URL }}
```

## GitLab CI

Use `include:` to pull the template into your top-level `.gitlab-ci.yml`:

```yaml
include:
  - local: 'examples/ci/gitlab-ci/aegis-pr-gate.gitlab-ci.yml'
```

Or extend the `.aegis-scan` hidden job from `aegis-scan.gitlab-ci.yml`.

## Jenkins

Paste `jenkins/Jenkinsfile` into your pipeline definition, or load the shared
library step from `jenkins/aegis-shared-library/`:

```groovy
@Library('your-shared-library') _

aegisScan scannerType: 'dependencies', blockOn: 'critical'
```

## Common patterns

### Block on critical only

```bash
aegis decide --block-on critical --exit-code
```

### Warn on high, block on critical

```bash
aegis decide --block-on critical --warn-on high --exit-code
```

### Post a report to a GitHub PR comment

```bash
aegis report --format markdown > report.md
gh pr comment "${PR_NUMBER}" --body-file report.md
```

### Run multiple scanner types

```bash
for scanner in dependencies sast container; do
  aegis scan --scanner "$scanner" --wait --json > "aegis-${scanner}.json"
done
aegis decide --block-on critical --exit-code
```

## Self-hosted runners / air-gapped environments

Install the CLI from your internal mirror:

```bash
pip install --index-url https://internal-pypi.example.com/simple/ aegis-cli
```

Set `AEGIS_BASE_URL` to your self-hosted Aegis backend URL.

## Validating locally

See [examples-test/README.md](examples-test/README.md) for instructions on
validating the templates before deploying them to your CI platform.
