"""Compute findings introduced by a PR by set-subtracting against the base SHA's findings."""
from __future__ import annotations


def compute_new_in_pr(
    *,
    head_findings: list[dict],
    base_findings: list[dict] | None,
) -> tuple[list[dict], bool]:
    """Return (new_findings, is_first_scan_on_base).

    `base_findings=None` means we have no completed scan on the base SHA;
    treat all head findings as "new" but flag is_first_scan_on_base=True so
    the comment can explain.

    `base_findings=[]` means we scanned and found nothing; subtract normally.
    """
    if base_findings is None:
        return list(head_findings), True

    base_keys = {f.get("fingerprint") for f in base_findings if f.get("fingerprint")}
    new = [f for f in head_findings if f.get("fingerprint") not in base_keys]
    return new, False
