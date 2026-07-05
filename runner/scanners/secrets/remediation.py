"""Deterministic, type-aware rotation runbooks for secret findings.

A leaked secret cannot be remediated with a code diff — the credential is
already public. Remediation is operational: revoke it at the provider, rotate
to a new one, repoint consumers, investigate blast radius, scrub it from git
history, then move the replacement into a vault and turn on push protection.

This module maps a TruffleHog detector to a provider-specific playbook and
emits a structured ``recommended_fix`` object (``kind="rotation"``). It runs
for every secret finding, is cheap, and is NOT gated on an LLM key. The runbook
is pure guidance — it performs no provider actions itself.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


# Shared trailing steps. Order is assigned at assembly time; these always sit
# after the provider-specific lifecycle so history-scrub can never precede the
# revoke step.
_SCRUB_STEP: dict[str, Any] = {
    "label": "Purge the secret from git history",
    "detail": (
        "Rewrite history with git-filter-repo (or BFG) to strip the value from "
        "every commit, then force-push and have all clones re-clone. Do this "
        "only after the credential is revoked — scrubbing history does not "
        "invalidate a still-active secret."
    ),
    "cli": "git filter-repo --replace-text replacements.txt",
    "url": "https://github.com/newren/git-filter-repo",
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
        "Turn on the host's secret push protection and add a pre-commit secret "
        "scanner (e.g. trufflehog or gitleaks) so the next leak is blocked "
        "before it reaches history."
    ),
    "url": (
        "https://docs.github.com/code-security/secret-scanning/"
        "push-protection-for-repositories-and-organizations"
    ),
}

_SHARED_TAIL: tuple[dict[str, Any], ...] = (_SCRUB_STEP, _VAULT_STEP, _PREVENT_STEP)


@dataclass(frozen=True)
class Playbook:
    """A provider's rotation lifecycle.

    ``provider`` is the human name surfaced in the runbook (``None`` for the
    generic fallback). ``lifecycle`` is the four provider-specific steps in
    canonical order: revoke, rotate, update consumers, investigate. The revoke
    step (index 0) must carry ``destructive: True`` — enforced at import.
    """

    provider: str | None
    lifecycle: tuple[dict[str, Any], ...]


_AWS = Playbook(
    provider="AWS",
    lifecycle=(
        {
            "label": "Disable, then delete the leaked AWS access key",
            "detail": (
                "Set the key to Inactive first to catch any consumer still "
                "using it, then delete it. The old key stops working at once."
            ),
            "url": "https://console.aws.amazon.com/iam/home#/security_credentials",
            "cli": (
                "aws iam update-access-key --access-key-id <KEY_ID> "
                "--status Inactive && aws iam delete-access-key "
                "--access-key-id <KEY_ID>"
            ),
            "destructive": True,
        },
        {
            "label": "Issue a replacement access key",
            "detail": (
                "Create a fresh key for the IAM principal, or better, switch "
                "the workload to an IAM role / short-lived credentials."
            ),
            "cli": "aws iam create-access-key --user-name <USERNAME>",
        },
        {
            "label": "Update every consumer to the new key",
            "detail": (
                "Roll the new key into CI, deploy targets, and any service that "
                "reads it, then confirm nothing still references the old key."
            ),
        },
        {
            "label": "Review CloudTrail for misuse",
            "detail": (
                "Search CloudTrail for activity tied to the leaked key during "
                "its exposure window and treat anything unexpected as an "
                "incident."
            ),
            "url": "https://console.aws.amazon.com/cloudtrail/home#/events",
        },
    ),
)

_GCP = Playbook(
    provider="Google Cloud (service account key)",
    lifecycle=(
        {
            "label": "Delete the leaked service-account key",
            "detail": (
                "Delete the exposed key version; it stops authenticating "
                "immediately."
            ),
            "url": "https://console.cloud.google.com/iam-admin/serviceaccounts",
            "cli": (
                "gcloud iam service-accounts keys delete <KEY_ID> "
                "--iam-account=<SA_EMAIL>"
            ),
            "destructive": True,
        },
        {
            "label": "Mint a replacement key (or move to Workload Identity)",
            "detail": (
                "Prefer Workload Identity Federation to eliminate static keys; "
                "if a key is unavoidable, create a new one."
            ),
            "cli": (
                "gcloud iam service-accounts keys create new-key.json "
                "--iam-account=<SA_EMAIL>"
            ),
        },
        {
            "label": "Update every consumer to the new credential",
            "detail": (
                "Replace the key in all workloads and CI, then confirm nothing "
                "still loads the old key file."
            ),
        },
        {
            "label": "Review Cloud Audit Logs for misuse",
            "detail": (
                "Inspect Cloud Audit Logs for calls made with the leaked key "
                "during its exposure window."
            ),
            "url": "https://console.cloud.google.com/logs",
        },
    ),
)

_GITHUB = Playbook(
    provider="GitHub",
    lifecycle=(
        {
            "label": "Revoke the exposed GitHub token",
            "detail": (
                "Delete the personal access token (or the OAuth/app "
                "credential) so it can no longer authenticate."
            ),
            "url": "https://github.com/settings/tokens",
            "destructive": True,
        },
        {
            "label": "Generate a replacement token",
            "detail": (
                "Create a new token — prefer a fine-grained token scoped to the "
                "minimum repos and permissions needed."
            ),
            "url": "https://github.com/settings/personal-access-tokens",
        },
        {
            "label": "Update every consumer to the new token",
            "detail": (
                "Roll the new token into CI secrets and any automation, then "
                "confirm the old token is unused."
            ),
        },
        {
            "label": "Review the account/org audit log for misuse",
            "detail": (
                "Check the security log for actions taken with the leaked token "
                "during its exposure window."
            ),
            "url": "https://github.com/settings/security-log",
        },
    ),
)

_OPENAI = Playbook(
    provider="OpenAI",
    lifecycle=(
        {
            "label": "Delete the exposed OpenAI API key",
            "detail": "Revoke the key from the dashboard; it stops working at once.",
            "url": "https://platform.openai.com/api-keys",
            "destructive": True,
        },
        {
            "label": "Create a replacement API key",
            "detail": (
                "Generate a new secret key, scoped to a dedicated project where "
                "possible."
            ),
            "url": "https://platform.openai.com/api-keys",
        },
        {
            "label": "Update every consumer to the new key",
            "detail": (
                "Replace the key everywhere it's read and confirm the old key "
                "is no longer referenced."
            ),
        },
        {
            "label": "Review usage for unexpected activity",
            "detail": (
                "Check the usage/activity dashboard for spend or calls you "
                "don't recognize during the exposure window."
            ),
            "url": "https://platform.openai.com/usage",
        },
    ),
)

_SLACK = Playbook(
    provider="Slack",
    lifecycle=(
        {
            "label": "Revoke the exposed Slack token",
            "detail": (
                "Revoke the token via the API (or rotate/reinstall the app); "
                "for an incoming webhook, deactivate it in the app config."
            ),
            "url": "https://api.slack.com/apps",
            "cli": "curl -X POST https://slack.com/api/auth.revoke -d token=<TOKEN>",
            "destructive": True,
        },
        {
            "label": "Reissue the token or webhook",
            "detail": (
                "Regenerate the bot/user token or recreate the incoming webhook "
                "URL."
            ),
            "url": "https://api.slack.com/apps",
        },
        {
            "label": "Update every consumer to the new credential",
            "detail": (
                "Roll the new token/webhook into all integrations and confirm "
                "the old one is unused."
            ),
        },
        {
            "label": "Review the Slack audit logs for misuse",
            "detail": (
                "Check access/audit logs for activity using the leaked token "
                "during its exposure window."
            ),
            "url": "https://api.slack.com/admins/audit-logs-api",
        },
    ),
)

_STRIPE = Playbook(
    provider="Stripe",
    lifecycle=(
        {
            "label": "Roll (revoke) the exposed Stripe API key",
            "detail": (
                "Roll the key from the dashboard; rolling immediately revokes "
                "the old key."
            ),
            "url": "https://dashboard.stripe.com/apikeys",
            "destructive": True,
        },
        {
            "label": "Issue a replacement key",
            "detail": (
                "Create a new secret (or restricted) key scoped to the minimum "
                "needed."
            ),
            "url": "https://dashboard.stripe.com/apikeys",
        },
        {
            "label": "Update every consumer to the new key",
            "detail": (
                "Replace the key across services and CI, then confirm nothing "
                "still uses the old key."
            ),
        },
        {
            "label": "Review API logs and events for misuse",
            "detail": (
                "Inspect the dashboard logs/events for requests made with the "
                "leaked key during its exposure window."
            ),
            "url": "https://dashboard.stripe.com/logs",
        },
    ),
)

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


# Keyed on the normalized provider token returned by ``_normalize_detector``.
DETECTOR_PLAYBOOKS: dict[str, Playbook] = {
    "aws": _AWS,
    "gcp": _GCP,
    "github": _GITHUB,
    "openai": _OPENAI,
    "slack": _SLACK,
    "stripe": _STRIPE,
}

# Detector-substring -> playbook key. Checked in order against the alphanumeric
# lowercase form of the detector, so TruffleHog variants ("AWSSessionKey",
# "GitHubApp", "SlackWebhook", ...) resolve to the right provider.
_PROVIDER_TOKENS: tuple[tuple[str, str], ...] = (
    ("aws", "aws"),
    ("gcp", "gcp"),
    ("googlecloud", "gcp"),
    ("github", "github"),
    ("openai", "openai"),
    ("slack", "slack"),
    ("stripe", "stripe"),
)


def _normalize_detector(detector: str) -> str:
    """Map a raw detector string to a playbook key (``"generic"`` if unknown)."""
    norm = re.sub(r"[^a-z0-9]", "", detector.lower())
    for token, key in _PROVIDER_TOKENS:
        if token in norm:
            return key
    return "generic"


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
    ``steps`` is never empty (the generic fallback covers unknown detectors).
    """
    detector = _detector_name(finding)
    playbook = DETECTOR_PLAYBOOKS.get(_normalize_detector(detector), _GENERIC)

    provider = playbook.provider or (detector or None)
    label = provider or "credential"
    if provider:
        title = f"Rotate the exposed {label} credential"
    else:
        title = "Rotate the exposed credential"

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
        "steps": _assemble_steps(playbook),
    }


def _validate_playbooks() -> None:
    """Fail loudly at import if any playbook breaks the revoke-first invariant."""
    catalog = {**DETECTOR_PLAYBOOKS, "generic": _GENERIC}
    for key, playbook in catalog.items():
        if not playbook.lifecycle:
            raise ValueError(f"playbook {key!r} has no lifecycle steps")
        revoke = playbook.lifecycle[0]
        if not revoke.get("destructive"):
            raise ValueError(
                f"playbook {key!r}: step 1 must be the destructive revoke step"
            )


_validate_playbooks()
