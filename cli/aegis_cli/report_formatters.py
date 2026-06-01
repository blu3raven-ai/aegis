"""Report formatters: Markdown, HTML, and JSON output for aegis report.

Each formatter receives the same `body` dict produced by the report command
and returns a string ready for stdout or file write.

Body schema (all keys optional except one of org/repo/chain):
  body["org"]      - org-level scope identifier
  body["repo"]     - single-repo scope
  body["chain"]    - single chain dict (from get_chain())
  body["findings"] - list of finding dicts
  body["since"]    - time window string, e.g. "7d"
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]


def _severity(finding: dict) -> str:
    """Extract normalised lowercase severity from any scanner finding shape."""
    sec_adv = finding.get("security_advisory") or {}
    s = (
        sec_adv.get("severity")
        or finding.get("severity")
        or (finding.get("rule") or {}).get("severity")
        or "unknown"
    )
    return str(s).lower()


def _risk_score(finding: dict) -> int:
    """Return a numeric risk proxy (higher = more urgent) for table sorting."""
    sev_scores = {"critical": 100, "high": 75, "medium": 50, "low": 25, "unknown": 0}
    score = sev_scores.get(_severity(finding), 0)
    # Boost reachable findings
    if finding.get("reachable"):
        score += 10
    return score


def _finding_title(finding: dict) -> str:
    dep = finding.get("dependency", {}) or {}
    pkg = dep.get("package", {}) or {}
    pkg_name = pkg.get("name", "")

    sec = finding.get("security_advisory", {}) or {}
    sec_title = sec.get("summary") or sec.get("description") or ""
    if sec_title:
        return sec_title[:60] + ("…" if len(sec_title) > 60 else "")

    rule = finding.get("rule", {}) or {}
    rule_desc = rule.get("description") or rule.get("id") or ""
    if rule_desc:
        return rule_desc[:60] + ("…" if len(rule_desc) > 60 else "")

    if pkg_name:
        version = finding.get("current_version", "")
        return f"{pkg_name}@{version}" if version else pkg_name

    return finding.get("title") or finding.get("id") or "Unknown finding"


def _finding_repo(finding: dict) -> str:
    repo = finding.get("repository", {}) or {}
    return repo.get("full_name") or finding.get("repo") or ""


def _finding_scanner(finding: dict) -> str:
    return finding.get("_scanner") or finding.get("scanner") or "unknown"


def _count_by_severity(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        sev = _severity(f)
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _scope_label(body: dict) -> str:
    if body.get("chain"):
        chain = body["chain"]
        return f"chain={chain.get('id', 'unknown')}"
    if body.get("repo"):
        return f"repo={body['repo']}"
    return f"org={body.get('org', 'unknown')}"


def _top_findings(findings: list[dict], n: int = 10) -> list[dict]:
    return sorted(findings, key=_risk_score, reverse=True)[:n]


def _age_label(finding: dict) -> str:
    """Return a human-readable age from created_at / discovered_at."""
    ts = finding.get("created_at") or finding.get("discovered_at") or ""
    if not ts:
        return "—"
    try:
        created = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        delta = datetime.now(timezone.utc) - created
        if delta.days == 0:
            mins = delta.seconds // 60
            return f"{mins} min" if mins else "< 1 min"
        return f"{delta.days}d"
    except ValueError:
        return "—"


def _chain_steps(chain: dict) -> list[str]:
    """Extract ordered step descriptions from a chain object."""
    steps = chain.get("steps") or chain.get("nodes") or []
    if isinstance(steps, list):
        result = []
        for s in steps:
            if isinstance(s, dict):
                result.append(s.get("description") or s.get("label") or str(s))
            else:
                result.append(str(s))
        return result
    return []


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def format_markdown(body: dict) -> str:
    """Render a Markdown security report."""
    findings: list[dict] = body.get("findings") or []
    since = body.get("since", "7d")
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    scope = _scope_label(body)

    counts = _count_by_severity(findings)

    lines: list[str] = []
    lines.append("# Aegis Security Report")
    lines.append("")
    lines.append(f"Generated: {now_iso}")
    lines.append(f"Scope: {scope}")
    lines.append(f"Window: last {since}")
    lines.append("")

    # --- Summary ---
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total findings: {len(findings)}")
    lines.append(
        f"- Critical: {counts['critical']} | High: {counts['high']} | "
        f"Medium: {counts['medium']} | Low: {counts['low']}"
    )

    # Chains
    chain_data = body.get("chain")
    if chain_data:
        chains_list = [chain_data] if isinstance(chain_data, dict) else chain_data
    else:
        chains_list = body.get("chains") or []
    lines.append(f"- Active chains: {len(chains_list)}")

    lines.append("- MTTR (median): —")
    lines.append("")

    # --- Critical Findings ---
    if findings:
        lines.append("## Critical Findings (top 10 by risk score)")
        lines.append("")
        lines.append("| # | Severity | Risk | Scanner | Title | Repo | Age |")
        lines.append("|---|---|---|---|---|---|---|")
        for i, f in enumerate(_top_findings(findings, 10), start=1):
            sev = _severity(f).capitalize()
            risk = _risk_score(f)
            scanner = _finding_scanner(f)
            title = _finding_title(f)
            repo = _finding_repo(f)
            age = _age_label(f)
            lines.append(f"| {i} | {sev} | {risk} | {scanner} | {title} | {repo} | {age} |")
        lines.append("")

    # --- Active Chains ---
    if chains_list:
        lines.append("## Active Chains")
        lines.append("")
        for ch in chains_list:
            ch_id = ch.get("id", "unknown")
            ch_title = ch.get("title") or ch.get("name") or ch_id
            ch_findings = ch.get("findings") or []
            ch_sev = ch.get("max_severity") or ch.get("severity") or "unknown"
            n = len(ch_findings) if isinstance(ch_findings, list) else ch.get("finding_count", 0)
            lines.append(f"- **{ch_title}** ({n} findings, severity max {ch_sev})")
            for step in _chain_steps(ch):
                lines.append(f"  1. {step}")
        lines.append("")

    # --- Findings by Repo ---
    if findings:
        lines.append("## Findings by Repo")
        lines.append("")
        repo_map: dict[str, dict[str, int]] = {}
        for f in findings:
            r = _finding_repo(f) or "unknown"
            sev = _severity(f)
            repo_map.setdefault(r, {})
            repo_map[r][sev] = repo_map[r].get(sev, 0) + 1

        for repo_name, sev_counts in sorted(repo_map.items()):
            parts = []
            for sev in _SEVERITY_ORDER:
                if sev in sev_counts and sev_counts[sev] > 0:
                    parts.append(f"{sev_counts[sev]} {sev}")
            lines.append(f"- {repo_name}: {' / '.join(parts) if parts else '0'}")
        lines.append("")

        # --- Findings by Scanner ---
        lines.append("## Findings by Scanner")
        lines.append("")
        scanner_map: dict[str, int] = {}
        for f in findings:
            sc = _finding_scanner(f)
            scanner_map[sc] = scanner_map.get(sc, 0) + 1

        for sc_name, sc_count in sorted(scanner_map.items()):
            lines.append(f"- {sc_name}: {sc_count}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_HTML_STYLE = """
<style>
  body { font-family: system-ui, sans-serif; max-width: 960px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; }
  h1 { border-bottom: 2px solid #e63946; padding-bottom: 8px; }
  h2 { border-bottom: 1px solid #ddd; padding-bottom: 4px; margin-top: 32px; }
  p.meta { color: #555; font-size: .9em; }
  table { border-collapse: collapse; width: 100%; margin: 16px 0; }
  th, td { text-align: left; padding: 8px 12px; border: 1px solid #ddd; font-size: .9em; }
  th { background: #f4f4f4; font-weight: 600; }
  tr:nth-child(even) { background: #fafafa; }
  .sev-critical { color: #c0392b; font-weight: 700; }
  .sev-high     { color: #e67e22; font-weight: 700; }
  .sev-medium   { color: #f1c40f; }
  .sev-low      { color: #27ae60; }
  ul { margin: 8px 0; padding-left: 20px; }
  li { margin: 4px 0; }
  @media print { body { margin: 0; } }
</style>
"""


def _html_escape(text: str) -> str:
    """Minimal HTML escaping to prevent XSS in user-controlled finding content."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def format_html(body: dict) -> str:
    """Render a single-file HTML security report with inline CSS."""
    findings: list[dict] = body.get("findings") or []
    since = body.get("since", "7d")
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    scope = _scope_label(body)

    counts = _count_by_severity(findings)

    chain_data = body.get("chain")
    if chain_data:
        chains_list = [chain_data] if isinstance(chain_data, dict) else chain_data
    else:
        chains_list = body.get("chains") or []

    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en">')
    parts.append("<head>")
    parts.append('<meta charset="UTF-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
    parts.append(f"<title>Aegis Security Report — {_html_escape(scope)}</title>")
    parts.append(_HTML_STYLE)
    parts.append("</head>")
    parts.append("<body>")
    parts.append("<h1>Aegis Security Report</h1>")
    parts.append(f'<p class="meta">Generated: {now_iso} &nbsp;|&nbsp; Scope: {_html_escape(scope)} &nbsp;|&nbsp; Window: last {_html_escape(since)}</p>')

    # Summary
    parts.append("<h2>Summary</h2>")
    parts.append("<ul>")
    parts.append(f"<li>Total findings: <strong>{len(findings)}</strong></li>")
    parts.append(
        f"<li>Critical: <span class='sev-critical'>{counts['critical']}</span> | "
        f"High: <span class='sev-high'>{counts['high']}</span> | "
        f"Medium: <span class='sev-medium'>{counts['medium']}</span> | "
        f"Low: <span class='sev-low'>{counts['low']}</span></li>"
    )
    parts.append(f"<li>Active chains: {len(chains_list)}</li>")
    parts.append("<li>MTTR (median): —</li>")
    parts.append("</ul>")

    # Top findings table
    if findings:
        parts.append("<h2>Critical Findings (top 10 by risk score)</h2>")
        parts.append("<table>")
        parts.append("<thead><tr><th>#</th><th>Severity</th><th>Risk</th><th>Scanner</th><th>Title</th><th>Repo</th><th>Age</th></tr></thead>")
        parts.append("<tbody>")
        for i, f in enumerate(_top_findings(findings, 10), start=1):
            sev = _severity(f)
            sev_class = f"sev-{sev}" if sev in ("critical", "high", "medium", "low") else ""
            risk = _risk_score(f)
            scanner = _html_escape(_finding_scanner(f))
            title = _html_escape(_finding_title(f))
            repo = _html_escape(_finding_repo(f))
            age = _html_escape(_age_label(f))
            parts.append(
                f"<tr><td>{i}</td>"
                f"<td><span class='{sev_class}'>{sev.capitalize()}</span></td>"
                f"<td>{risk}</td><td>{scanner}</td><td>{title}</td>"
                f"<td>{repo}</td><td>{age}</td></tr>"
            )
        parts.append("</tbody></table>")

    # Active chains
    if chains_list:
        parts.append("<h2>Active Chains</h2>")
        parts.append("<ul>")
        for ch in chains_list:
            ch_title = _html_escape(ch.get("title") or ch.get("name") or ch.get("id", "unknown"))
            ch_findings = ch.get("findings") or []
            ch_sev = _html_escape(ch.get("max_severity") or ch.get("severity") or "unknown")
            n = len(ch_findings) if isinstance(ch_findings, list) else ch.get("finding_count", 0)
            parts.append(f"<li><strong>{ch_title}</strong> ({n} findings, severity max {ch_sev})")
            steps = _chain_steps(ch)
            if steps:
                parts.append("<ol>")
                for step in steps:
                    parts.append(f"<li>{_html_escape(step)}</li>")
                parts.append("</ol>")
            parts.append("</li>")
        parts.append("</ul>")

    # By repo
    if findings:
        parts.append("<h2>Findings by Repo</h2>")
        parts.append("<ul>")
        repo_map: dict[str, dict[str, int]] = {}
        for f in findings:
            r = _finding_repo(f) or "unknown"
            sev = _severity(f)
            repo_map.setdefault(r, {})
            repo_map[r][sev] = repo_map[r].get(sev, 0) + 1

        for repo_name, sev_counts in sorted(repo_map.items()):
            p = []
            for sev in _SEVERITY_ORDER:
                if sev in sev_counts and sev_counts[sev] > 0:
                    p.append(f"{sev_counts[sev]} {sev}")
            parts.append(f"<li>{_html_escape(repo_name)}: {_html_escape(' / '.join(p) if p else '0')}</li>")
        parts.append("</ul>")

        # By scanner
        parts.append("<h2>Findings by Scanner</h2>")
        parts.append("<ul>")
        scanner_map: dict[str, int] = {}
        for f in findings:
            sc = _finding_scanner(f)
            scanner_map[sc] = scanner_map.get(sc, 0) + 1
        for sc_name, sc_count in sorted(scanner_map.items()):
            parts.append(f"<li>{_html_escape(sc_name)}: {sc_count}</li>")
        parts.append("</ul>")

    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def format_json(body: dict) -> str:
    """Serialise the report body as indented JSON.

    datetime objects are rendered as ISO strings via the `default` handler.
    """
    return json.dumps(body, indent=2, default=str)
