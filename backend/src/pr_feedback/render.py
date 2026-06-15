"""Render the sticky PR comment markdown."""
from __future__ import annotations

from collections import Counter

MARKER_PREFIX = "<!-- aegis-pr-feedback:"

_VERDICT_LABELS = {
    "confirmed": "Confirmed",
    "needs_verify": "Needs verify",
    "possible": "Possible",
    "ruled_out": "Ruled out",
}


def _severity_bucket(sev: str) -> str:
    s = (sev or "").lower()
    if s in ("critical", "high"):
        return "high"
    if s == "medium":
        return "medium"
    if s in ("low", "info", "informational"):
        return "low"
    return "low"


def render_sticky_comment(
    *,
    scan_id: str,
    aegis_url: str,
    source_id: str,
    pr_number: int,
    new_findings: list[dict],
    is_first_scan_on_base: bool,
) -> str:
    total = len(new_findings)
    deep_link = f"{aegis_url.rstrip('/')}/sources/{source_id}/findings?pr={pr_number}"

    header_marker = f"{MARKER_PREFIX}scan={scan_id} -->"

    if total == 0:
        body_status = "✅ **No new findings introduced by this PR.**\n"
    else:
        verdict_counts = Counter(
            f.get("verdict") for f in new_findings if f.get("verdict")
        )
        if verdict_counts:
            rows = "\n".join(
                f"| {label} | {verdict_counts.get(key, 0)} |"
                for key, label in _VERDICT_LABELS.items()
                if verdict_counts.get(key, 0) > 0
            )
            body_status = (
                f"🚨 **{total} new findings introduced by this PR.**\n"
                "\n"
                "| Verdict | Count |\n"
                "|---|---|\n"
                f"{rows}\n"
            )
        else:
            counts = Counter(
                _severity_bucket(f.get("severity", "")) for f in new_findings
            )
            body_status = (
                f"🚨 **{total} new findings introduced by this PR.**\n"
                "\n"
                "| Severity | Count |\n"
                "|---|---|\n"
                f"| 🔴 High | {counts.get('high', 0)} |\n"
                f"| 🟡 Medium | {counts.get('medium', 0)} |\n"
                f"| ⚪ Low | {counts.get('low', 0)} |\n"
            )

    baseline_note = ""
    if is_first_scan_on_base:
        baseline_note = (
            "\n"
            "_First scan on this base — no prior baseline; all findings on this PR are listed as new._\n"
        )

    footer = (
        "\n"
        f"→ Triage in Aegis: {deep_link}\n"
        "\n"
        "_Detailed evidence, ownership, fix workflow, and dismissal are managed in the Aegis portal._\n"
    )

    return (
        "🛡️ **Aegis security scan**\n"
        f"{header_marker}\n"
        "\n"
        + body_status
        + baseline_note
        + footer
    )
