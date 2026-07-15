"""Locks in rules 4 and 5 of the backend / runner boundary from
docs/architecture.md.

Rule 4: backend never knows about tool-specific output shapes.
Rule 5: backend never executes scanner tools.

Any file under backend/src that calls a subprocess primitive or names a
scanner tool fails this test, unless its path is on EXEMPT_FILES with a
comment explaining why.
"""
from __future__ import annotations

import re
from pathlib import Path

BACKEND_SRC = Path(__file__).resolve().parents[2] / "backend" / "src"


SCANNER_TOOLS = (
    "trivy",
    "grype",
    "syft",
    "semgrep",
    "joern",
    "trufflehog",
    "bandit",
    "kics",
    "checkov",
    "osv-scanner",
)


SUBPROCESS_PATTERNS = (
    r"\bsubprocess\.run\b",
    r"\bsubprocess\.Popen\b",
    r"\bsubprocess\.call\b",
    r"\bsubprocess\.check_output\b",
    r"\basyncio\.create_subprocess_exec\b",
    r"\basyncio\.create_subprocess_shell\b",
    r"\bos\.system\b",
    r"\bos\.popen\b",
)


TOOL_SCHEMA_PATTERNS = (
    r"\btrivy_vulnerability\b",
    r"\btrivy_resource\b",
    r"\btrivy_misconfiguration\b",
    r"\bsemgrep_rule_id\b",
    r"\bsemgrep_check_id\b",
    r"\bsemgrep_match\b",
    r"\bgrype_match\b",
    r"\bgrype_metadata\b",
    r"\bsyft_artifact\b",
    r"\bsyft_relationship\b",
    r"\btrufflehog_result\b",
    r"\btrufflehog_detector\b",
    r"\bjoern_finding\b",
    r"\bjoern_query\b",
)


# Files explicitly allowed to violate the rules above. Each entry MUST have
# a one-line reason. Adding a file here is a deliberate decision.
EXEMPT_FILES: tuple[tuple[str, str], ...] = (
    # alembic upgrade subprocess at startup — non-scanner migration bootstrap
    ("main.py", "alembic upgrade subprocess at startup"),
    # MinIO `mc` CLI subprocess for bucket init — non-scanner
    ("storage_init.py", "MinIO mc CLI subprocess for bucket init"),
    # Tool labels (catalog metadata + classification branches on the
    # canonical `source` field, not tool-output parsing)
    ("secrets/scanner.py", "label-only branch on canonical source field"),
    ("secrets/periodic_sweep.py", "comment-only mention of detector version"),
    ("shared/enrichment.py", "comment + label-only branch in advisory enrichment"),
    # Connector catalog metadata (registry entries name the tool as a string label)
    ("integrations/ci_wizards.py", "catalog metadata names tools as labels"),
    # Canonical-schema engine label defaulting (no tool-output parsing)
    ("code_scanning/ingest.py", "defaults canonical `engine` label to 'semgrep'"),
    ("containers/scanner.py", "module docstring names runner-side pipeline"),
    # IaC ingest: docstrings name the runner-side tool; lifecycle defaults the
    # canonical `engine` label (no tool execution or tool-output parsing).
    ("iac/__init__.py", "package docstring names runner-side IaC tool"),
    ("iac/ingest.py", "docstring names runner-side IaC tool; ingests canonical findings"),
    ("iac/lifecycle.py", "docstring + canonical `engine` label default"),
    ("iac/scanner.py", "module docstring names runner-side IaC tool"),
    # SBOM components carry a `source_tool` label (canonical schema field)
    ("containers/sbom_store.py", "label-only `source_tool` field on SBOM components"),
    ("graphql/sbom_resolvers.py", "filter on canonical `source_tool` label"),
    ("sbom/resolvers.py", "filter on canonical `source_tool` label"),
    # BYO router accepts findings from any out-of-band scanner — the docstring
    # describes accepted formats but the router never executes any scanner.
    ("scans/byo_router.py", "docstring names BYO scanner examples; no execution or parsing"),
    # DB CHECK constraint enumerates valid label values for the `engine` column
    ("db/models.py", "CHECK constraint enumerates valid engine label values"),
)

_EXEMPT_PATHS = frozenset(rel for rel, _ in EXEMPT_FILES)


_ALL_PATTERNS = (
    [(name, re.compile(r"\b" + re.escape(name) + r"\b", re.IGNORECASE))
     for name in SCANNER_TOOLS]
    + [(pat, re.compile(pat)) for pat in SUBPROCESS_PATTERNS]
    + [(pat, re.compile(pat)) for pat in TOOL_SCHEMA_PATTERNS]
)


def _scan_file(path: Path) -> list[tuple[int, str, str]]:
    hits: list[tuple[int, str, str]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return hits
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        for label, regex in _ALL_PATTERNS:
            if regex.search(line):
                hits.append((line_no, label, line.strip()))
    return hits


def _iter_backend_files() -> list[Path]:
    return sorted(
        p for p in BACKEND_SRC.rglob("*.py")
        if "/tests/" not in str(p) and "__pycache__" not in str(p)
    )


def test_backend_never_executes_or_parses_scanner_tools() -> None:
    offenders: list[str] = []
    for path in _iter_backend_files():
        rel = path.relative_to(BACKEND_SRC).as_posix()
        if rel in _EXEMPT_PATHS:
            continue
        hits = _scan_file(path)
        if hits:
            for line_no, label, line in hits:
                offenders.append(f"{rel}:{line_no}: {label} -> {line}")
    assert not offenders, (
        "Backend files violate the runner / backend boundary "
        "(docs/architecture.md, rules 4 & 5). Either move the code to "
        "runner/, delete it, or add the file's path to EXEMPT_FILES with "
        "a comment explaining why:\n  - " + "\n  - ".join(offenders)
    )
