"""Compose a confirmed finding into a security-advisory Markdown document and a
downloadable proof-of-concept artifact.

Pure functions of the finding dict produced by ``_finding_to_dict(..., hydrate=
True)`` — no DB access, no auth. The caller is responsible for scope + permission
gating before handing a finding here. Sections with no data are omitted; the
Testing & Safe Harbor footer and the PoC file header are static templates and are
never model-authored.
"""
from __future__ import annotations

import html

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


def _safe_filename(name: str, fallback: str) -> str:
    """Header-safe download filename: keep only alnum / dot / dash / underscore
    so a model-supplied poc_filename can't break out of the quoted
    Content-Disposition value. Falls back when nothing usable remains."""
    cleaned = "".join(c if (c.isalnum() or c in "._-") else "-" for c in name).strip("-.")
    return cleaned or fallback


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
    ro = (m.get("ruled_out_reason") or {})
    if ro.get("source") == "accepted_risk":
        parts.append(f"Ruled out — accepted risk: {ro.get('statement')}\n")

    parts.append(_SAFE_HARBOR)
    return "\n".join(parts)


_PDF_CSS = """
@page { size: A4; margin: 2cm; }
body { font-family: "Helvetica Neue", Arial, sans-serif; font-size: 11px; color: #1a1a1a; line-height: 1.5; }
h1 { font-size: 18px; margin: 0 0 8px; }
h2 { font-size: 13px; margin: 18px 0 6px; border-bottom: 1px solid #ddd; padding-bottom: 3px; }
p { margin: 4px 0; }
.impact { color: #444; }
.meta { margin: 6px 0 12px; }
.meta div { margin: 2px 0; }
.meta .k { display: inline-block; width: 90px; font-weight: 600; color: #555; }
code { font-family: monospace; background: #f4f4f4; padding: 1px 4px; border-radius: 3px; font-size: 10px; }
pre { font-family: monospace; background: #f7f7f7; border: 1px solid #e3e3e3; border-radius: 4px; padding: 8px; font-size: 10px; white-space: pre-wrap; word-break: break-all; }
ul, ol { margin: 4px 0 4px 18px; padding: 0; }
"""


def _esc(value: object) -> str:
    return html.escape(str(value))


def compose_advisory_html(finding: dict) -> str:
    """Render the advisory as a standalone, print-styled HTML document for the
    PDF exporter. Every finding-derived string is HTML-escaped — the renderer
    requires callers to escape untrusted content — and the section selection
    mirrors compose_advisory_markdown."""
    m = _meta(finding)
    title = (finding.get("title") or "Security Finding").strip()
    body: list[str] = [f"<h1>{_esc(title)}</h1>"]

    impact = (m.get("impact") or "").strip()
    if impact:
        body.append(f'<p class="impact"><strong>Impact:</strong> {_esc(impact)}</p>')

    rows: list[str] = []
    if finding.get("repo"):
        rows.append(f'<div><span class="k">Target</span>{_esc(finding["repo"])}</div>')
    sev = (finding.get("severity") or "").strip()
    if sev:
        rows.append(f'<div><span class="k">Severity</span>{_esc(sev.capitalize())}</div>')
    if m.get("cvss_vector"):
        sc = m.get("cvss_score")
        val = f'<code>{_esc(m["cvss_vector"])}</code>' + (f" = {_esc(sc)}" if sc is not None else "")
        rows.append(f'<div><span class="k">CVSS 3.1</span>{val}</div>')
    if finding.get("cwe"):
        rows.append(f'<div><span class="k">CWE</span>{_esc(finding["cwe"])}</div>')
    if finding.get("cve"):
        rows.append(f'<div><span class="k">CVE</span>{_esc(finding["cve"])}</div>')
    if rows:
        body.append('<div class="meta">' + "".join(rows) + "</div>")

    chain = (finding.get("exploit_chain") or "").strip()
    if chain:
        body.append(f"<h2>Summary</h2><p>{_esc(chain)}</p>")

    evidence = finding.get("evidence") or []
    if isinstance(evidence, list) and evidence:
        body.append("<h2>Technical Detail</h2>")
        for i, ev in enumerate(evidence, start=1):
            if not isinstance(ev, dict):
                continue
            loc = f"{ev.get('file', '?')}:{ev.get('line', '?')}"
            kind = ev.get("kind", "")
            label = f'<strong>[R{i}] <code>{_esc(loc)}</code></strong>'
            if kind:
                label += f" ({_esc(kind)})"
            body.append(f"<p>{label}</p>")
            snippet = (ev.get("snippet") or "").strip()
            if snippet:
                body.append(f"<pre>{_esc(snippet)}</pre>")

    repro = (m.get("reproduction") or "").strip()
    paths = [p for p in (m.get("attack_paths") or [])
             if isinstance(p, dict) and str(p.get("steps") or "").strip()]
    if repro or paths:
        body.append("<h2>Attack Scenario</h2>")
        if repro:
            body.append(f"<p>{_esc(repro)}</p>")
        for p in paths:
            body.append(
                f"<p><strong>{_esc(p.get('name', 'Path'))}</strong> — {_esc(p['steps'].strip())}</p>"
            )

    factors = [f.strip() for f in (m.get("mitigating_factors") or [])
               if isinstance(f, str) and f.strip()]
    if factors:
        body.append("<h2>Mitigating Factors</h2><ul>"
                    + "".join(f"<li>{_esc(f)}</li>" for f in factors) + "</ul>")

    distinct = (m.get("distinctness") or "").strip()
    if distinct:
        body.append(f"<h2>Distinctness</h2><p>{_esc(distinct)}</p>")

    fix = (m.get("fix") or "").strip()
    steps = [s.strip() for s in (m.get("remediation") or [])
             if isinstance(s, str) and s.strip()]
    if fix or steps:
        body.append("<h2>Remediation</h2>")
        if fix:
            body.append(f"<pre>{_esc(fix)}</pre>" if ("@@" in fix or "+++" in fix) else f"<p>{_esc(fix)}</p>")
        if steps:
            body.append("<ol>" + "".join(f"<li>{_esc(s)}</li>" for s in steps) + "</ol>")

    verdict = (finding.get("verdict") or "").strip()
    if verdict:
        body.append(f"<h2>Notes</h2><p>Verification verdict: <strong>{_esc(verdict)}</strong>.</p>")
    ro = (m.get("ruled_out_reason") or {})
    if ro.get("source") == "accepted_risk":
        body.append(f"<p>Ruled out — accepted risk: {_esc(ro.get('statement') or '')}</p>")

    body.append(
        "<h2>Testing &amp; Safe Harbor</h2>"
        "<p>All testing was performed locally against the open-source code with benign "
        "proof-of-concept payloads. No production systems or user data were accessed, "
        "and there was no impact to availability. This report is kept confidential "
        "pending a fix.</p>"
    )

    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        f"<style>{_PDF_CSS}</style></head><body>"
        + "".join(body)
        + "</body></html>"
    )


def poc_artifact(finding: dict) -> tuple[str, str] | None:
    """Return (filename, script_with_safe_harbor_header) for a finding that has a
    PoC, else None."""
    m = _meta(finding)
    script = (m.get("poc_script") or "").strip()
    if not script:
        return None
    lang = (m.get("poc_language") or "").strip().lower()
    ext = _LANG_EXT.get(lang, "txt")
    fallback = f"finding-{finding.get('id', 'x')}-poc.{ext}"
    # Model-supplied filename is untrusted output; keep only chars that can't
    # break out of the quoted Content-Disposition header value.
    name = _safe_filename((m.get("poc_filename") or "").strip(), fallback)
    comment = "#" if lang in ("python", "bash", "sh", "ruby", "php", "") else "//"
    header = _POC_HEADER_TMPL.format(
        comment=comment,
        title=(finding.get("title") or "finding").strip(),
        target=finding.get("repo", "n/a"),
    )
    return name, header + script + "\n"
