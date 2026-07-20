"""Deterministic rotation runbook for secret findings.

A leaked secret cannot be remediated with a code diff — the credential is
already public. Remediation is operational: revoke it at the provider, rotate
to a new one, repoint consumers, investigate blast radius, scrub it from git
history, then move the replacement into a vault and turn on push protection.

One generic playbook covers every secret type. The detector name (e.g.
"GitHub", "AWS") is surfaced as the credential label so the runbook still reads
"Rotate the exposed GitHub credential", but no provider-specific rotation URLs
are hardcoded — those are wrong for self-hosted GitLab/Gitea and add no value
for SaaS the operator already knows how to reach. The runbook is pure guidance;
it performs no provider actions itself.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# Shared trailing steps. Order is assigned at assembly time; these always sit
# after the lifecycle so history-scrub can never precede the revoke step.
_SCRUB_STEP: dict[str, Any] = {
    "label": "Purge the secret from git history",
    "detail": (
        "Rewrite history with git-filter-repo (or BFG) to strip the value from "
        "every commit, then force-push and have all clones re-clone. Do this "
        "only after the credential is revoked — scrubbing history does not "
        "invalidate a still-active secret."
    ),
    "cli": "git filter-repo --replace-text replacements.txt",
    "destructive": True,
}

_VAULT_STEP: dict[str, Any] = {
    "label": "Move the new credential into a secret manager",
    "detail": (
        "Store the replacement in a managed secret store (HashiCorp Vault, "
        "AWS/GCP Secret Manager, etc.) and inject it at runtime instead of "
        "committing it to the repository."
    ),
}

_PREVENT_STEP: dict[str, Any] = {
    "label": "Enable push protection and pre-commit secret scanning",
    "detail": (
        "Turn on your git host's secret push protection and add a pre-commit "
        "secret scanner (e.g. trufflehog or gitleaks) so the next leak is "
        "blocked before it reaches history."
    ),
}

_SHARED_TAIL: tuple[dict[str, Any], ...] = (_SCRUB_STEP, _VAULT_STEP, _PREVENT_STEP)


@dataclass(frozen=True)
class Playbook:
    """A rotation lifecycle.

    ``provider`` is the human name surfaced in the runbook (``None`` for the
    generic fallback, in which case the detector name is used as the label).
    ``lifecycle`` is the canonical-order steps: revoke, rotate, update
    consumers, investigate. The revoke step (index 0) must carry
    ``destructive: True`` — enforced at import.
    """

    provider: str | None
    lifecycle: tuple[dict[str, Any], ...]


_GENERIC = Playbook(
    provider=None,
    lifecycle=(
        {
            "label": "Revoke or disable the exposed credential at its provider",
            "detail": (
                "Use the provider's console or API to revoke/disable the "
                "credential now. A leaked secret cannot be fixed with a code "
                "change — it must be invalidated."
            ),
            "destructive": True,
        },
        {
            "label": "Issue a replacement credential",
            "detail": (
                "Generate a new credential scoped to the minimum access "
                "required."
            ),
        },
        {
            "label": "Update every consumer to the new credential",
            "detail": (
                "Roll the replacement into all services, CI, and config, then "
                "confirm nothing still references the old value."
            ),
        },
        {
            "label": "Review the provider's audit/access logs for misuse",
            "detail": (
                "Look for activity using the leaked credential during its "
                "exposure window and treat anything unexpected as an incident."
            ),
        },
    ),
)


def _detector_name(finding: dict[str, Any]) -> str:
    """Read the detector name from a finding across TruffleHog/canonical keys."""
    for key in ("DetectorName", "detector", "DetectorType", "ruleID"):
        val = finding.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def _verified_flag(finding: dict[str, Any]) -> bool:
    """Whether the provider confirmed the secret is live (TruffleHog Verified)."""
    for key in ("Verified", "verified"):
        if key in finding:
            return bool(finding[key])
    return False


def _assemble_steps(playbook: Playbook) -> list[dict[str, Any]]:
    """Combine the lifecycle + shared tail and assign 1-based ordering."""
    ordered: list[dict[str, Any]] = []
    for index, step in enumerate(playbook.lifecycle + _SHARED_TAIL, start=1):
        ordered.append({"order": index, **step})
    return ordered


def build_secret_runbook(finding: dict[str, Any]) -> dict[str, Any]:
    """Return the ``recommended_fix`` rotation object for a secret finding.

    Deterministic and always-on: the same finding always yields the same
    runbook. The first step is always the destructive provider-side revoke and
    ``steps`` is never empty. The detector name surfaces as the credential
    label; the steps are the generic rotation lifecycle.
    """
    detector = _detector_name(finding)
    provider = detector or None
    title = f"Rotate the exposed {provider} credential" if provider else "Rotate the exposed credential"

    if detector:
        rationale = (
            f"Flagged by the '{detector}' secret detector. A committed "
            "credential is already exposed and cannot be remediated by editing "
            "code — it must be revoked and rotated."
        )
    else:
        rationale = (
            "Flagged by the secret scanner. A committed credential is already "
            "exposed and cannot be remediated by editing code — it must be "
            "revoked and rotated."
        )

    return {
        "kind": "rotation",
        "source": "deterministic",
        "title": title,
        "description": (
            "A leaked credential is already public — revoke it at the provider, "
            "rotate to a new one, repoint consumers, then scrub it from history "
            "and prevent recurrence."
        ),
        "rationale": rationale,
        "provider": provider,
        "verifiedActive": _verified_flag(finding),
        "steps": _assemble_steps(_GENERIC),
    }


def _validate_playbook() -> None:
    """Fail loudly at import if the playbook breaks the revoke-first invariant."""
    if not _GENERIC.lifecycle:
        raise ValueError("generic playbook has no lifecycle steps")
    if not _GENERIC.lifecycle[0].get("destructive"):
        raise ValueError("generic playbook: step 1 must be the destructive revoke step")


_validate_playbook()
