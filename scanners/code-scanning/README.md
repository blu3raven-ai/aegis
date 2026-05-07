# SAST Scanner

Opengrep-based Docker image for static analysis of Git repositories. Outputs `findings.jsonl` for ingestion by the vulnerability management portal.

## Usage

```bash
docker run --rm \
  -e GIT_REPOS="https://github.com/org/repo1,https://github.com/org/repo2" \
  -e GIT_TOKEN="your-token" \
  -e ORG_LABEL="myorg" \
  -v /host/output:/scanner/output \
  ghcr.io/u9u-p/security/sast-scanner:latest
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `GIT_REPOS` | — | Comma-separated repo clone URLs (or path to a newline-separated file) |
| `GIT_TOKEN` | — | Auth token for private repos (passed via GIT_ASKPASS, never exposed in process list) |
| `ORG_LABEL` | `default` | Label for output directory grouping |
| `CONCURRENCY` | `4` | Number of repositories to scan in parallel |
| `RUN_ID` | timestamp | Unique run identifier |
| `RULESETS` | bundled | Comma-separated ruleset identifiers. Named rulesets (`p/owasp-top-ten`) use bundled rules; absolute paths are passed through directly |

## Output

```
/scanner/output/{ORG_LABEL}/runs/{RUN_ID}/
├── raw/{org}/{repo}/
│   ├── head-sha.txt          # HEAD commit SHA
│   └── opengrep.json         # Raw SARIF output from Opengrep
└── normalized/
    └── findings.jsonl        # One JSON object per line
```

Each line in `findings.jsonl`:

```json
{
  "repo_full_name": "org/repo",
  "file_path": "src/app.py",
  "start_line": 42,
  "end_line": 42,
  "rule_id": "python.lang.security.audit.sqli.sql-injection",
  "rule_name": "SQL Injection",
  "severity": "critical",
  "confidence": "high",
  "category": "security",
  "cwe": ["CWE-89"],
  "message": "...",
  "snippet": "cursor.execute(query)",
  "fix_suggestion": null,
  "commit_sha": "abc123",
  "stateCandidate": "open"
}
```

## Bundled Rules

At build time, security rules are sparse-cloned from `semgrep/semgrep-rules` (pinned SHA):

- `python/lang/security`
- `javascript/lang/security`
- `typescript/lang/security`
- `java/lang/security`
- `go/lang/security`
- `ruby/lang/security`
- `php/lang/security`
- `generic/` (cross-language secrets, CI rules)

## Building

```bash
docker build -t sast-scanner:local -f dockerfile .
```
