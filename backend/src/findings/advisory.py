"""Compose a confirmed finding into a security-advisory Markdown document and a
downloadable proof-of-concept artifact.

Pure functions of the finding dict produced by ``_finding_to_dict(..., hydrate=
True)`` — no DB access, no auth. The caller is responsible for scope + permission
gating before handing a finding here. Sections with no data are omitted; the
Testing & Safe Harbor footer and the PoC file header are static templates and are
never model-authored.
"""
from __future__ import annotations

from typing import Any

_LANG_EXT = {"python": "py", "bash": "sh", "sh": "sh", "javascript": "js",
             "typescript": "ts", "ruby": "rb", "go": "go", "php": "php"}

_SAFE_HARBOR = (
    "## Testing & Safe Harbor\n\n"
    "All testing was performed locally against the open-source code with benign "
    "proof-of-concept payloads. No production systems or user data were accessed, "
    "and there was no impact to availability. This report is kept confidential "
    "pending a fix.\n"
)

_POC_HEADER_TMPL = (
    "{comment} Proof of concept — {title}\n"
    "{comment} Target: {target}\n"
    "{comment}\n"
    "{comment} SAFE HARBOR: benign reachability proof only. This script proves the\n"
    "{comment} vulnerable code path is reachable using a harmless marker. It performs\n"
    "{comment} no exfiltration and no destructive action. Run only against systems you\n"
    "{comment} are authorised to test.\n\n"
)


def _meta(finding: dict) -> dict:
    m = finding.get("verification_metadata")
    return m if isinstance(m, dict) else {}


def compose_advisory_markdown(finding: dict) -> str:
    m = _meta(finding)
    title = (finding.get("title") or "Security Finding").strip()
    parts: list[str] = [f"# {title}\n"]

    impact = (m.get("impact") or "").strip()
    if impact:
        parts.append(f"**Impact:** {impact}\n")

    header: list[str] = []
    if finding.get("repo"):
        header.append(f"**Target:** {finding['repo']}")
    sev = (finding.get("severity") or "").strip()
    if sev:
        header.append(f"**Severity:** {sev.capitalize()}")
    if m.get("cvss_vector"):
        vec = m["cvss_vector"]
        sc = m.get("cvss_score")
        header.append(f"**CVSS 3.1:** `{vec}`" + (f" = {sc}" if sc is not None else ""))
    if finding.get("cwe"):
        header.append(f"**CWE:** {finding['cwe']}")
    if finding.get("cve"):
        header.append(f"**CVE:** {finding['cve']}")
    if header:
        parts.append("\n".join(header) + "\n")

    chain = (finding.get("exploit_chain") or "").strip()
    if chain:
        parts.append(f"## Summary\n\n{chain}\n")

    evidence = finding.get("evidence") or []
    if isinstance(evidence, list) and evidence:
        lines = ["## Technical Detail\n"]
        for i, ev in enumerate(evidence, start=1):
            if not isinstance(ev, dict):
                continue
            loc = f"{ev.get('file', '?')}:{ev.get('line', '?')}"
            kind = ev.get("kind", "")
            snippet = (ev.get("snippet") or "").strip()
            lines.append(f"**[R{i}]** `{loc}`" + (f" ({kind})" if kind else ""))
            if snippet:
                lines.append(f"```\n{snippet}\n```")
        parts.append("\n".join(lines) + "\n")

    repro = (m.get("reproduction") or "").strip()
    paths = [p for p in (m.get("attack_paths") or [])
             if isinstance(p, dict) and str(p.get("steps") or "").strip()]
    if repro or paths:
        lines = ["## Attack Scenario\n"]
        if repro:
            lines.append(repro)
        for p in paths:
            lines.append(f"**{p.get('name', 'Path')}** — {p['steps'].strip()}")
        parts.append("\n\n".join(lines) + "\n")

    factors = [f.strip() for f in (m.get("mitigating_factors") or [])
               if isinstance(f, str) and f.strip()]
    if factors:
        parts.append("## Mitigating Factors\n\n"
                     + "\n".join(f"- {f}" for f in factors) + "\n")

    distinct = (m.get("distinctness") or "").strip()
    if distinct:
        parts.append(f"## Distinctness\n\n{distinct}\n")

    fix = (m.get("fix") or "").strip()
    steps = [s.strip() for s in (m.get("remediation") or [])
             if isinstance(s, str) and s.strip()]
    if fix or steps:
        lines = ["## Remediation\n"]
        if fix:
            lines.append(f"```\n{fix}\n```" if ("@@" in fix or "+++" in fix) else fix)
        for i, s in enumerate(steps, start=1):
            lines.append(f"{i}. {s}")
        parts.append("\n".join(lines) + "\n")

    verdict = (finding.get("verdict") or "").strip()
    if verdict:
        parts.append(f"## Notes\n\nVerification verdict: **{verdict}**.\n")

    parts.append(_SAFE_HARBOR)
    return "\n".join(parts)


def poc_artifact(finding: dict) -> tuple[str, str] | None:
    """Return (filename, script_with_safe_harbor_header) for a finding that has a
    PoC, else None."""
    m = _meta(finding)
    script = (m.get("poc_script") or "").strip()
    if not script:
        return None
    lang = (m.get("poc_language") or "").strip().lower()
    name = (m.get("poc_filename") or "").strip()
    if not name:
        ext = _LANG_EXT.get(lang, "txt")
        name = f"finding-{finding.get('id', 'x')}-poc.{ext}"
    comment = "#" if lang in ("python", "bash", "sh", "ruby", "php", "") else "//"
    header = _POC_HEADER_TMPL.format(
        comment=comment,
        title=(finding.get("title") or "finding").strip(),
        target=finding.get("repo", "n/a"),
    )
    return name, header + script + "\n"
