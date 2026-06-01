# Aegis Policy Examples

These files demonstrate the three common postures for an Aegis decision policy.
Copy one to `.aegis/policy.yml` in your project and customise from there.

## Postures

| File | Posture | Best for |
|------|---------|----------|
| `block-on-critical.yml` | Strict — CI fails on critical or high-EPSS | Production, regulated environments |
| `warn-on-high.yml` | Moderate — CI fails only on critical, warns on high | Internal tools, growth-stage projects |
| `monitor-only.yml` | Observability — never fails CI | Legacy onboarding, initial visibility |

## Policy Schema

```yaml
# Each entry under block_on / warn_on / allow is evaluated in order.
# The first matching rule wins.

block_on:
  - severity: critical        # Match by severity: critical | high | medium | low
  - epss_above: 0.7           # Match when EPSS exploitation probability > threshold

warn_on:
  - severity: high

allow:
  - severity: low
  - default: true             # Catch-all — must be the last entry if used

exclude_paths:
  - "tests/**"                # Glob patterns relative to the repo root
  - "**/__pycache__/**"       # Patterns must be quoted to avoid YAML parser issues

exclude_packages:
  - example-package@1.2.3    # Suppress a specific package version
```

### Fields

**`block_on`** — findings matching any rule here cause CI to fail with a `block` verdict.

**`warn_on`** — findings matching here are surfaced as warnings but do not fail CI.

**`allow`** — findings matching here are permitted without any annotation.

**`exclude_paths`** — file path globs (relative to repo root) whose findings are suppressed entirely.
Use quotes around patterns containing `*` to avoid YAML parsing issues.

**`exclude_packages`** — package identifiers (`name@version`) whose findings are suppressed.
Omit the version to suppress all versions of a package.

### Severity levels

`critical` > `high` > `medium` > `low`

### EPSS

[EPSS](https://www.first.org/epss/) (Exploit Prediction Scoring System) is a probability
score (0–1) estimating the likelihood of a vulnerability being exploited in the wild within
30 days.  Use `epss_above` to tighten gates on actively-exploited CVEs regardless of CVSS
severity.

## Activating a policy

Reference the policy file from `.aegis.yml`:

```yaml
policy_file: .aegis/policy.yml
```

`aegis init` creates `.aegis/policy.yml` with the `block-on-critical` posture by default.
