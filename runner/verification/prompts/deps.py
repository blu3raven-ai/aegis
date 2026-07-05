"""Single-shot reachability prompt for dependency (SCA) findings."""
from __future__ import annotations

DEPS_REACHABILITY_SYSTEM = """You are a senior application security engineer judging whether a known-vulnerable dependency is actually reachable in this codebase.

You are given:
- The vulnerable package and the advisory (summary, description, affected version range, and any affected functions/symbols it names).
- The call-sites where the package is imported or referenced in the repository (file + line + verbatim source).

Decide whether the vulnerable code path can be reached from this repository's use of the package:
- `reachable`  — the code invokes the vulnerable symbol / feature described by the advisory (or uses the package in a way that plausibly exercises it).
- `no_path`    — the package is imported but the vulnerable symbol / feature is provably NOT exercised (e.g. only an unrelated, unaffected API is used).
- `unknown`    — you cannot tell from the given call-sites and advisory. This is the correct answer whenever you are unsure.

Rules:
- NEVER guess `no_path`. Only answer `no_path` when the call-sites concretely show the vulnerable symbol is not used; otherwise answer `unknown`.
- Every evidence snippet MUST be copied verbatim from a provided call-site, with its real file and line. Never invent file paths or line numbers.

Respond ONLY with valid JSON in this exact shape:
{
  "reachability": "reachable" | "no_path" | "unknown",
  "evidence": [
    {"file": "<path>", "line": <int>, "snippet": "<verbatim from a call-site>", "kind": "import_site" | "sink" | "context"}
  ]
}"""


def deps_reachability_user_message(
    finding: dict,
    advisory_context: str,
    call_sites: list[dict],
) -> str:
    pkg = finding.get("packageName") or finding.get("package") or ""
    version = finding.get("packageVersion") or finding.get("version") or ""
    advisory_id = finding.get("cve") or finding.get("advisoryId") or finding.get("advisory_id") or ""

    sites = "\n".join(
        f"  {c.get('file')}:{c.get('line')}: {c.get('snippet')}" for c in call_sites
    ) or "  (none extracted)"

    return (
        "Vulnerable dependency:\n"
        f"  package: {pkg}\n"
        f"  version: {version}\n"
        f"  advisory: {advisory_id}\n"
        "\n"
        f"Advisory:\n{advisory_context or '  (no advisory text available)'}\n"
        "\n"
        f"Call-sites in the repository:\n{sites}\n"
    )
