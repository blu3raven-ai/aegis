"""Output formatters for terminal (Rich) and machine-readable (JSON) output."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box

_SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
}

_DECISION_COLORS = {
    "block": "bold red",
    "warn": "yellow",
    "allow": "bold green",
}

console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def format_findings_table(findings: list[dict[str, Any]]) -> str:
    """Render findings as a Rich terminal table."""
    if not findings:
        return "[dim]No findings.[/dim]"

    table = Table(
        box=box.SIMPLE_HEAD,
        show_lines=False,
        expand=False,
        padding=(0, 1),
    )
    table.add_column("Severity", style="bold", no_wrap=True)
    table.add_column("Scanner", no_wrap=True)
    table.add_column("Package / Rule", overflow="fold")
    table.add_column("Advisory / ID", overflow="fold")
    table.add_column("Repository", overflow="fold")
    table.add_column("State", no_wrap=True)

    for f in findings:
        sev = _extract_severity(f)
        color = _SEVERITY_COLORS.get(sev.lower(), "")
        scanner = f.get("_scanner") or f.get("scanner", "")
        pkg = _extract_package(f)
        advisory = _extract_advisory(f)
        repo = f.get("repo") or (f.get("repository") or {}).get("full_name") or ""
        state = f.get("state", "open")

        table.add_row(
            Text(sev.upper() if sev else "?", style=color),
            scanner,
            pkg,
            advisory,
            repo,
            state,
        )

    from io import StringIO
    from rich.console import Console as _Con

    buf = StringIO()
    c = _Con(file=buf, highlight=False)
    c.print(table)
    return buf.getvalue()


def format_findings_json(findings: list[dict[str, Any]]) -> str:
    """Serialize findings as indented JSON for CI parsing."""
    return json.dumps(findings, indent=2, default=str)


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------


def format_decision(
    decision: dict[str, Any], *, exit_code_mode: bool = False
) -> str:
    """Render a go/no-go decision with colour coding.

    In exit_code_mode the output is terse (suitable for CI log noise
    reduction); colour is preserved for human readability.
    """
    verdict = decision.get("decision", "unknown")
    color = _DECISION_COLORS.get(verdict.lower(), "bold white")
    rationale = decision.get("rationale", "")
    source = decision.get("source", "backend")
    blockers = decision.get("blockers") or []

    lines: list[str] = []
    lines.append(f"[{color}]{verdict.upper()}[/{color}]  {rationale}")

    if source == "local":
        lines.append("[dim](decision computed locally — backend endpoint not available)[/dim]")

    if blockers and not exit_code_mode:
        lines.append(f"\n[bold]Blocking findings ({len(blockers)}):[/bold]")
        for b in blockers[:10]:
            sev = _extract_severity(b)
            col = _SEVERITY_COLORS.get(sev.lower(), "")
            pkg = _extract_package(b)
            adv = _extract_advisory(b)
            lines.append(f"  [{col}]{sev.upper():8s}[/{col}]  {pkg}  {adv}")
        if len(blockers) > 10:
            lines.append(f"  … and {len(blockers) - 10} more")

    from io import StringIO
    from rich.console import Console as _Con

    buf = StringIO()
    c = _Con(file=buf, highlight=False)
    for line in lines:
        c.print(line)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Scan status
# ---------------------------------------------------------------------------


def format_scan_status(run: dict[str, Any]) -> str:
    """Render a scan run summary."""
    run_id = run.get("id", "?")
    status = run.get("status", "unknown")
    org = run.get("org", "")
    findings = run.get("findingsCount") or run.get("counts", {}).get("total", "?")
    progress = run.get("progress") or {}
    pct = progress.get("percent", 0)
    stage = progress.get("stage") or status

    lines = [
        f"[bold]Run:[/bold] {run_id}",
        f"[bold]Org:[/bold] {org}",
        f"[bold]Status:[/bold] {_status_colored(status)}  ({stage}  {pct}%)",
        f"[bold]Findings:[/bold] {findings}",
    ]
    if run.get("startedAt"):
        lines.append(f"[bold]Started:[/bold] {run['startedAt']}")
    if run.get("finishedAt"):
        lines.append(f"[bold]Finished:[/bold] {run['finishedAt']}")
    if run.get("error"):
        lines.append(f"[bold red]Error:[/bold red] {run['error']}")

    from io import StringIO
    from rich.console import Console as _Con

    buf = StringIO()
    c = _Con(file=buf, highlight=False)
    for line in lines:
        c.print(line)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_severity(finding: dict) -> str:
    sec_adv = finding.get("security_advisory") or {}
    if sec_adv.get("severity"):
        return sec_adv["severity"]
    return finding.get("severity") or (finding.get("rule") or {}).get("severity", "")


def _extract_package(finding: dict) -> str:
    # Aggregated endpoint shape — already a flat "package" string.
    pkg_flat = finding.get("package")
    if pkg_flat:
        return pkg_flat
    dep = finding.get("dependency") or {}
    pkg = (dep.get("package") or {}).get("name") or ""
    version = finding.get("current_version") or ""
    if version:
        return f"{pkg}@{version}"
    # code scanning: rule description
    rule = finding.get("rule") or {}
    fallback = rule.get("description") or rule.get("id") or pkg or ""
    if fallback:
        return fallback
    # Aggregated endpoint may carry only title / file_path for SAST + secrets.
    return finding.get("title") or finding.get("file_path") or ""


def _extract_advisory(finding: dict) -> str:
    sec_adv = finding.get("security_advisory") or {}
    cve = sec_adv.get("cve_id") or sec_adv.get("ghsa_id") or ""
    return (
        cve
        or finding.get("cve")
        or finding.get("rule", {}).get("id")
        or finding.get("fingerprint")
        or finding.get("id")
        or ""
    )


def _status_colored(status: str) -> str:
    mapping = {
        "completed": "[bold green]completed[/bold green]",
        "running": "[yellow]running[/yellow]",
        "queued": "[dim]queued[/dim]",
        "failed": "[bold red]failed[/bold red]",
        "cancelled": "[dim red]cancelled[/dim red]",
        "ingesting": "[yellow]ingesting[/yellow]",
    }
    return mapping.get(status, status)
