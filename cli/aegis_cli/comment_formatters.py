"""PR comment formatters for aegis comment.

Each formatter receives a `payload` dict with the following schema and returns
a platform-ready Markdown string:

  payload["findings"]        list[dict]  — finding dicts (same shape as get_findings())
  payload["chains"]          list[dict]  — chain dicts (optional)
  payload["decision"]        dict        — go/no-go dict with "decision" key (optional)
  payload["total_findings"]  int         — total count before max_findings truncation
  payload["scan_id"]         str         — scan identifier (optional)
  payload["base_url"]        str         — Aegis instance URL for deeplinks

Platform quirks handled:
  - GitHub / GitLab: <details> collapsible blocks for individual findings
  - Bitbucket: no <details> support — flat numbered list instead
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# Severity emoji used across all platform formatters
_SEV_EMOJI: dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "unknown": "⚪",
}

# Severity sort order (most urgent first)
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]


# ---------------------------------------------------------------------------
# Shared helpers (re-use logic from report_formatters where semantics match)
# ---------------------------------------------------------------------------

def _severity(finding: dict) -> str:
    sec_adv = finding.get("security_advisory") or {}
    s = (
        sec_adv.get("severity")
        or finding.get("severity")
        or (finding.get("rule") or {}).get("severity")
        or "unknown"
    )
    return str(s).lower()


def _risk_score(finding: dict) -> int:
    sev_scores = {"critical": 100, "high": 75, "medium": 50, "low": 25, "unknown": 0}
    score = sev_scores.get(_severity(finding), 0)
    if finding.get("reachable"):
        score += 10
    return score


def _finding_title(finding: dict) -> str:
    sec = finding.get("security_advisory") or {}
    title = sec.get("summary") or sec.get("description") or ""
    if title:
        return title[:80] + ("…" if len(title) > 80 else "")

    rule = finding.get("rule") or {}
    rule_desc = rule.get("description") or rule.get("id") or ""
    if rule_desc:
        return rule_desc[:80] + ("…" if len(rule_desc) > 80 else "")

    dep = finding.get("dependency") or {}
    pkg = (dep.get("package") or {}).get("name", "")
    if pkg:
        ver = finding.get("current_version", "")
        return f"{pkg}@{ver}" if ver else pkg

    return finding.get("title") or finding.get("id") or "Unknown finding"


def _finding_repo(finding: dict) -> str:
    repo = finding.get("repository") or {}
    return repo.get("full_name") or finding.get("repo") or ""


def _finding_location(finding: dict) -> str:
    """Best-effort file:line from wherever the scanner stores it."""
    loc = finding.get("location") or finding.get("most_recent_instance") or {}
    if isinstance(loc, dict):
        path = loc.get("path") or loc.get("file") or ""
        line = loc.get("start_line") or loc.get("line") or ""
        if path and line:
            return f"`{path}:{line}`"
        if path:
            return f"`{path}`"
    return ""


def _finding_cve(finding: dict) -> str:
    sec = finding.get("security_advisory") or {}
    cves = sec.get("cve_ids") or []
    if cves:
        return cves[0]
    return sec.get("cve_id") or ""


def _finding_fix(finding: dict) -> str:
    """Extract a concise remediation hint from the finding."""
    # Dependencies scanner: first patched version
    dep = finding.get("dependency") or {}
    first_patched = (dep.get("vulnerableVersionRange") or "")
    # Try advisory patched versions
    sec = finding.get("security_advisory") or {}
    patched = sec.get("patched_versions") or []
    pkg_name = (dep.get("package") or {}).get("name", "")
    if patched and pkg_name:
        return f"Upgrade `{pkg_name}` to `{patched[0]}`"
    if patched:
        return f"Upgrade to `{patched[0]}`"
    # SAST / secrets: use rule message
    msg = (finding.get("rule") or {}).get("full_description") or ""
    if msg:
        return msg[:120] + ("…" if len(msg) > 120 else "")
    return finding.get("fix") or finding.get("remediation") or ""


def _count_by_severity(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        sev = _severity(f)
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _decision_line(decision: dict | None) -> str:
    """Format a single decision outcome line."""
    if not decision:
        return ""
    outcome = (decision.get("decision") or "unknown").lower()
    if outcome == "block":
        icon = "❌ Block"
    elif outcome == "allow":
        icon = "✅ Allow"
    else:
        icon = f"⚠️ {outcome.capitalize()}"
    return icon


def _severity_table(counts: dict[str, int]) -> list[str]:
    lines = [
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in _SEVERITY_ORDER:
        n = counts.get(sev, 0)
        if n == 0:
            continue
        emoji = _SEV_EMOJI.get(sev, "")
        lines.append(f"| {emoji} {sev.capitalize()} | {n} |")
    return lines


# ---------------------------------------------------------------------------
# GitHub / GitLab formatter (identical collapse syntax)
# ---------------------------------------------------------------------------

def _format_github_gitlab(
    payload: dict,
    *,
    platform: str,
) -> str:
    """Shared implementation for GitHub and GitLab — both support <details>."""
    findings: list[dict] = payload.get("findings") or []
    chains: list[dict] = payload.get("chains") or []
    decision: dict | None = payload.get("decision")
    total: int = payload.get("total_findings", len(findings))
    base_url: str = (payload.get("base_url") or "https://aegis.example.org").rstrip("/")
    scan_id: str = payload.get("scan_id") or ""

    counts = _count_by_severity(findings)
    has_critical_or_high = (counts.get("critical", 0) + counts.get("high", 0)) > 0

    lines: list[str] = []

    # Header
    lines.append("## 🛡️ Aegis Security Report")
    lines.append("")

    # Severity summary table
    lines.extend(_severity_table(counts))
    lines.append("")

    # Top findings section (critical + high only shown in collapsibles)
    if findings:
        if has_critical_or_high:
            lines.append("### Top findings")
            lines.append("")
            for f in findings:
                sev = _severity(f)
                if sev not in ("critical", "high"):
                    continue
                emoji = _SEV_EMOJI.get(sev, "")
                title = _finding_title(f)
                repo = _finding_repo(f)
                cve = _finding_cve(f)
                location = _finding_location(f)
                fix = _finding_fix(f)
                risk = _risk_score(f)

                summary_parts = [f"{emoji} {title}"]
                if repo:
                    summary_parts.append(f"· {repo}")
                if cve:
                    summary_parts.append(f"· {cve}")
                summary_str = " ".join(summary_parts)

                lines.append("<details>")
                lines.append(f"<summary><strong>{summary_str}</strong></summary>")
                lines.append("")
                if location:
                    lines.append(f"**Location:** {location}")
                lines.append(f"**Risk score:** {risk}/100")
                if fix:
                    lines.append(f"**Fix:** {fix}")
                lines.append("")
                lines.append("</details>")
                lines.append("")
        else:
            # No critical/high — show a brief note
            lines.append("### Top findings")
            lines.append("")
            lines.append("No critical or high severity findings.")
            lines.append("")
    else:
        lines.append("_No findings in this scan._")
        lines.append("")

    # Chains section
    if chains:
        lines.append("### Chains")
        lines.append("")
        for ch in chains:
            ch_id = ch.get("id") or ""
            ch_title = ch.get("title") or ch.get("name") or ch_id
            ch_sev = ch.get("max_severity") or ch.get("severity") or "unknown"
            ch_findings = ch.get("findings") or []
            n = len(ch_findings) if isinstance(ch_findings, list) else ch.get("finding_count", 0)
            chain_url = f"{base_url}/chains/{ch_id}" if ch_id else base_url
            lines.append(
                f"- **{ch_title}** in "
                f"{_chain_repos(ch)} ({n} findings, {ch_sev}) "
                f"→ [view chain]({chain_url})"
            )
        lines.append("")

    # Decision section
    if decision:
        outcome = _decision_line(decision)
        rationale = decision.get("rationale") or ""
        repo_hint = decision.get("repo") or ""
        lines.append(f"### Decision: {outcome}")
        lines.append("")
        if rationale:
            lines.append(f"> {rationale}")
        else:
            lines.append(f"> Aegis recommends {'blocking' if 'Block' in outcome else 'allowing'} deploys.")
        if repo_hint:
            lines.append(f"> Repository: `{repo_hint}`")
        lines.append("")

    # Footer
    findings_url = f"{base_url}/findings"
    if scan_id:
        findings_url = f"{base_url}/findings?scan={scan_id}"
    lines.append("---")
    lines.append(
        f"<sub>Generated by [Aegis]({base_url}) · "
        f"{total} findings in this PR · "
        f"[View full report]({findings_url})</sub>"
    )

    return "\n".join(lines)


def format_github_comment(payload: dict) -> str:
    """Render a GitHub PR comment from scan findings."""
    return _format_github_gitlab(payload, platform="github")


def format_gitlab_comment(payload: dict) -> str:
    """Render a GitLab MR comment from scan findings.

    GitLab renders <details> the same way GitHub does, but note-level
    discussion threads use a slightly different anchor scheme.  The Markdown
    body itself is identical.
    """
    return _format_github_gitlab(payload, platform="gitlab")


# ---------------------------------------------------------------------------
# Bitbucket formatter — no <details> support, flat numbered list
# ---------------------------------------------------------------------------

def format_bitbucket_comment(payload: dict) -> str:
    """Render a Bitbucket PR comment from scan findings.

    Bitbucket's Markdown renderer does not support <details>/<summary>
    collapse syntax, so top findings are rendered as a flat numbered list.
    """
    findings: list[dict] = payload.get("findings") or []
    chains: list[dict] = payload.get("chains") or []
    decision: dict | None = payload.get("decision")
    total: int = payload.get("total_findings", len(findings))
    base_url: str = (payload.get("base_url") or "https://aegis.example.org").rstrip("/")
    scan_id: str = payload.get("scan_id") or ""

    counts = _count_by_severity(findings)
    has_critical_or_high = (counts.get("critical", 0) + counts.get("high", 0)) > 0

    lines: list[str] = []

    lines.append("## Aegis Security Report")
    lines.append("")

    # Severity table (plain — Bitbucket renders GFM tables)
    lines.extend(_severity_table(counts))
    lines.append("")

    # Top findings — flat list
    if findings:
        if has_critical_or_high:
            lines.append("### Top findings")
            lines.append("")
            idx = 1
            for f in findings:
                sev = _severity(f)
                if sev not in ("critical", "high"):
                    continue
                emoji = _SEV_EMOJI.get(sev, "")
                title = _finding_title(f)
                repo = _finding_repo(f)
                cve = _finding_cve(f)
                location = _finding_location(f)
                fix = _finding_fix(f)
                risk = _risk_score(f)

                meta_parts = []
                if repo:
                    meta_parts.append(repo)
                if cve:
                    meta_parts.append(cve)
                meta = f" ({', '.join(meta_parts)})" if meta_parts else ""

                lines.append(f"{idx}. **{emoji} {title}**{meta}")
                if location:
                    lines.append(f"   - Location: {location}")
                lines.append(f"   - Risk score: {risk}/100")
                if fix:
                    lines.append(f"   - Fix: {fix}")
                idx += 1
            lines.append("")
        else:
            lines.append("### Top findings")
            lines.append("")
            lines.append("No critical or high severity findings.")
            lines.append("")
    else:
        lines.append("_No findings in this scan._")
        lines.append("")

    # Chains section
    if chains:
        lines.append("### Chains")
        lines.append("")
        for ch in chains:
            ch_id = ch.get("id") or ""
            ch_title = ch.get("title") or ch.get("name") or ch_id
            ch_sev = ch.get("max_severity") or ch.get("severity") or "unknown"
            ch_findings = ch.get("findings") or []
            n = len(ch_findings) if isinstance(ch_findings, list) else ch.get("finding_count", 0)
            chain_url = f"{base_url}/chains/{ch_id}" if ch_id else base_url
            lines.append(
                f"- **{ch_title}** in "
                f"{_chain_repos(ch)} ({n} findings, {ch_sev}) "
                f"- [view chain]({chain_url})"
            )
        lines.append("")

    # Decision section
    if decision:
        outcome = _decision_line(decision)
        rationale = decision.get("rationale") or ""
        lines.append(f"### Decision: {outcome}")
        lines.append("")
        if rationale:
            lines.append(f"> {rationale}")
        lines.append("")

    # Footer (Bitbucket supports basic Markdown links)
    findings_url = f"{base_url}/findings"
    if scan_id:
        findings_url = f"{base_url}/findings?scan={scan_id}"
    lines.append("---")
    lines.append(
        f"Generated by [Aegis]({base_url}) · "
        f"{total} findings · "
        f"[View full report]({findings_url})"
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _chain_repos(chain: dict) -> str:
    """Extract a comma-joined repo list from a chain object."""
    repos: list[str] = chain.get("repos") or chain.get("repositories") or []
    if isinstance(repos, list) and repos:
        return ", ".join(str(r) for r in repos[:3])
    # Fall back to chain-level repo hint
    return chain.get("repo") or chain.get("repository") or "unknown"
