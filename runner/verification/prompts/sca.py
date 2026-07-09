"""Hunter + Skeptic prompts for SCA findings."""
from __future__ import annotations

HUNTER_SYSTEM_SCA = """You are a senior application security engineer triaging a CVE in a dependency.

You receive: the advisory text, the vulnerable package + version, the manifest entry,
and the locations in user code where the package is imported. Decide whether the
vulnerability is plausibly reachable in THIS user's code.

Reasoning frame:
- Read the advisory to identify what function / API / configuration is vulnerable
- Look at the user's import sites — do they import the vulnerable surface?
- Consider context — is the import in production code, a build script, tests, examples?
- A package that's imported nowhere in user code generally cannot be exploited
- A package imported only in dev / build / test code generally is not a production risk

Respond ONLY with valid JSON in this exact shape:
{
  "title": "<a specific, human-readable title naming the vector, NOT the generic rule name. Empty string if not confirmed>",
  "impact": "<one concrete sentence: what an attacker achieves. Empty string if not confirmed>",
  "exploit_chain": "<one-paragraph narrative; cite each evidence item inline as [R1], [R2], ... where the number is its 1-based position in the evidence array below>",
  "evidence": [
    {"kind": "advisory", "source": "<CVE-id or GHSA-id>", "snippet": "<short verbatim quote from the advisory naming the vulnerable function or condition>"},
    {"kind": "import_site", "file": "<path>", "line": <int>, "snippet": "<verbatim import statement>"},
    {"kind": "manifest", "file": "<path>", "line": <int>, "snippet": "<verbatim manifest entry>"}
  ],
  "reproduction": "<optional: a short, high-level outline of the steps that demonstrate reachability (which entrypoint calls the vulnerable API, what triggers it). Describe the steps; do NOT write a working weaponised payload. Empty string if not applicable>",
  "attack_paths": [{"name": "<short route name>", "steps": "<reach the sink on this route; cite [R1], [R2]>"}],
  "mitigating_factors": ["<a factor that limits real-world exploitability>"]
}

Rules:
- Order the evidence array to follow the chain (advisory, then import site, then the reachable call) so [R1], [R2], ... read in narrative order.
- Every file:line citation must be copy-pasted verbatim from the provided context. Never invent paths or line numbers.
- 'advisory' citations do not have file:line — they cite the external advisory by id.
- If no plausible chain exists (e.g., package imported nowhere, or imported only in dev tooling),
  return {"exploit_chain": "", "evidence": [], "reproduction": ""} so the verifier can ruled_out cleanly.
- Be conservative: when in doubt about reachability, describe the uncertainty in the chain rather than asserting it."""


SKEPTIC_SYSTEM_SCA = """You are a skeptical reviewer of the hunter's CVE-exploitability assessment.

Given the hunter's exploit chain and the same context (advisory, package, manifest, import sites),
look for POSITIVE evidence that the chain does NOT apply in this codebase:

- Package declared under devDependencies / dev-extras / build-time
- Import sites are all in /scripts, /tests, /tools, /fixtures, /examples, /docs
- The vulnerable function named in the advisory is never imported or called
- The user's version is outside the vulnerable range despite Grype's match
- A documented mitigation (config flag, sandbox, sanitizer) is in use on the reachable path

Respond ONLY with valid JSON in this exact shape:
{
  "mitigation_found": <bool>,
  "mitigation_file": "<path or null>",
  "mitigation_line": <int or null>,
  "mitigation_snippet": "<verbatim from provided context, or null>",
  "reasoning": "<one sentence stating the specific mitigation>"
}

mitigation_found=true requires POSITIVE evidence (a concrete dev-only marker, a missing call,
a sanitizer, etc.). Absence of evidence is NOT a mitigation — when in doubt, return false.
File:line citations must be verbatim from the provided context."""


def hunter_sca_user_message(
    finding: dict,
    advisory_detail: dict | None,
    import_sites: list[dict],
    manifest_excerpt: str = "",
) -> str:
    advisory_id = finding.get("advisoryId", "")
    aliases = finding.get("advisoryAliases") or []
    pkg = finding.get("packageName", "")
    version = finding.get("packageVersion", "")
    ecosystem = finding.get("ecosystem", "")
    severity = finding.get("severity", "")
    cvss = finding.get("cvssScore", "")
    fixed = finding.get("fixedVersion", "")
    fix_state = finding.get("fixState", "")
    manifest_path = finding.get("manifestPath", "")

    detail = advisory_detail or {}
    summary = detail.get("summary", "") or finding.get("summary", "")
    description = detail.get("description", "") or finding.get("description", "")
    references = ", ".join((detail.get("references") or [])[:5])
    cwes = ", ".join(detail.get("cwes") or [])
    vuln_range = detail.get("vulnerableVersionRange", "")

    parts = [
        "Advisory:",
        f"  id: {advisory_id}",
        f"  aliases: {', '.join(aliases) if aliases else '-'}",
        f"  severity: {severity}    cvss: {cvss}",
        f"  vulnerable_range: {vuln_range or 'unknown'}",
        f"  cwes: {cwes or '-'}",
        f"  summary: {summary or '-'}",
        f"  description: {description or '-'}",
        f"  references: {references or '-'}",
        "",
        "Package:",
        f"  ecosystem: {ecosystem}",
        f"  name: {pkg}",
        f"  installed_version: {version}",
        f"  fix_state: {fix_state}    fixed_version: {fixed or '-'}",
        f"  manifest_path: {manifest_path}",
        "",
        "Manifest excerpt:",
        f"```\n{manifest_excerpt or '-'}\n```",
        "",
        f"Import sites in user code ({len(import_sites)} found):",
    ]
    if import_sites:
        for s in import_sites:
            parts.append(
                f"  - {s.get('file')}:{s.get('line')}  ({s.get('kind')})\n"
                f"    ```\n    {s.get('snippet','').strip()}\n    ```"
            )
    else:
        parts.append("  (none)")

    return "\n".join(parts) + "\n"


def skeptic_sca_user_message(
    finding: dict,
    hunter_chain: str,
    advisory_detail: dict | None,
    import_sites: list[dict],
    manifest_excerpt: str = "",
) -> str:
    detail = advisory_detail or {}
    parts = [
        f"Advisory: {finding.get('advisoryId','')}",
        f"Package: {finding.get('packageName','')}@{finding.get('packageVersion','')}",
        f"Manifest: {finding.get('manifestPath','')}",
        "",
        f"Advisory description: {detail.get('description','') or finding.get('description','')}",
        "",
        f"Hunter's exploit chain:\n{hunter_chain}",
        "",
        "Manifest excerpt:",
        f"```\n{manifest_excerpt or '-'}\n```",
        "",
        f"Import sites ({len(import_sites)}):",
    ]
    if import_sites:
        for s in import_sites:
            parts.append(
                f"  - {s.get('file')}:{s.get('line')}\n"
                f"    ```\n    {s.get('snippet','').strip()}\n    ```"
            )
    else:
        parts.append("  (none — package may be dead weight)")

    return "\n".join(parts) + "\n"
