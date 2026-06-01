# Validating CI templates locally

Quick smoke-test commands to lint and validate the templates before pushing them
to a live CI/CD platform.

## Prerequisites

Install the relevant linters:

```bash
# GitHub Actions linter (https://github.com/rhysd/actionlint)
brew install actionlint           # macOS
# or
go install github.com/rhysd/actionlint/cmd/actionlint@latest

# GitLab CI lint — requires a running GitLab instance or the gitlab-ci-lint CLI
pip install gitlab-ci-lint

# Jenkins declarative linter — requires a running Jenkins instance
# https://www.jenkins.io/doc/book/pipeline/development/#linter
```

## GitHub Actions

```bash
actionlint examples/ci/github-actions/aegis-scan.yml
actionlint examples/ci/github-actions/aegis-pr-gate.yml
actionlint examples/ci/github-actions/action.yml
```

## GitLab CI

```bash
gitlab-ci-lint examples/ci/gitlab-ci/aegis-scan.gitlab-ci.yml
gitlab-ci-lint examples/ci/gitlab-ci/aegis-pr-gate.gitlab-ci.yml
```

Alternatively, validate via the GitLab API:

```bash
curl --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  --data-urlencode "content@examples/ci/gitlab-ci/aegis-scan.gitlab-ci.yml" \
  "https://gitlab.example.com/api/v4/ci/lint"
```

## Jenkins

```bash
jenkins-cli declarative-linter < examples/ci/jenkins/Jenkinsfile
```

## YAML syntax (quick check, no external tools needed)

```bash
python3 -c '
import yaml, glob, sys
files = glob.glob("examples/ci/**/*.yml", recursive=True) + \
        glob.glob("examples/ci/**/*.yaml", recursive=True)
ok = True
for f in files:
    try:
        yaml.safe_load(open(f))
        print(f"  ok  {f}")
    except yaml.YAMLError as e:
        print(f"  ERR {f}: {e}", file=sys.stderr)
        ok = False
sys.exit(0 if ok else 1)
'
```

## Local run with `act` (GitHub Actions)

[`act`](https://github.com/nektos/act) lets you run GitHub Actions workflows
locally using Docker:

```bash
# Install act
brew install act    # macOS

# Dry-run the PR gate workflow
act pull_request \
  --secret AEGIS_API_TOKEN="<your-token>" \
  --secret AEGIS_BASE_URL="https://aegis.example.com" \
  --workflows examples/ci/github-actions/aegis-pr-gate.yml \
  --dryrun
```

## GitLab CI with `gitlab-runner exec`

```bash
gitlab-runner exec docker aegis-scan \
  --env AEGIS_API_TOKEN="<your-token>" \
  --env AEGIS_BASE_URL="https://aegis.example.com"
```
