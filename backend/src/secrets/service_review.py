from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from src.storage import VALID_REVIEW_STATUSES, read_secrets_snapshot


def normalize_review_updates(updates: list[dict[str, Any]], valid_statuses: set[str]) -> tuple[list[dict[str, Any]] | None, str | None]:
    normalized_updates: list[dict[str, Any]] = []
    for item in updates:
        fingerprint = str(item.get("fingerprint") or "").strip()
        if not fingerprint:
            return None, "Invalid fingerprint in updates payload"
        status = item.get("status")
        if status not in valid_statuses:
            return None, f"Invalid review status: {status}"
        scope = item.get("scope") or ("secret" if item.get("secretIdentity") else "occurrence")
        normalized_updates.append(
            {
                "fingerprint": fingerprint,
                "status": status,
                "secretIdentity": item.get("secretIdentity"),
                "scope": scope,
                "repository": item.get("repository"),
                "source": item.get("source"),
                "detector": item.get("detector"),
                "filePath": item.get("filePath"),
                "line": item.get("line"),
                "commit": item.get("commit"),
            }
        )
    return normalized_updates, None


def _stamp_resolution_timestamps(
    finding: dict[str, Any],
    old_status: str,
    new_status: str,
    now_iso: str,
) -> dict[str, Any]:
    """Stamp confirmedAt/resolvedAt on a finding based on the status transition.

    Transitions:
      new -> confirmed:     set confirmedAt
      new -> false_positive: set resolvedAt
      confirmed -> action_taken: set resolvedAt
      any -> new (undo):    clear confirmedAt and resolvedAt
    """
    updated = dict(finding)
    if new_status == "confirmed" and old_status == "new":
        updated["confirmedAt"] = now_iso
    elif new_status == "false_positive" and old_status in ("new", "confirmed"):
        updated["resolvedAt"] = now_iso
    elif new_status == "action_taken" and old_status == "confirmed":
        updated["resolvedAt"] = now_iso
    elif new_status == "new":
        updated["confirmedAt"] = None
        updated["resolvedAt"] = None
    return updated


def apply_review_updates(
    org: str,
    updates: list[dict[str, Any]],
    *,
    user_id: str | None = None,
    user_role: str | None = None,
    user_role_id: str | None = None,
) -> tuple[dict[str, Any], int]:
    org = (org or "").strip()
    if not org:
        return {"error": "Missing org in request body"}, 400
    if not updates:
        return {"error": "Missing updates payload"}, 400

    normalized_updates, error = normalize_review_updates(updates, VALID_REVIEW_STATUSES)
    if error:
        return {"error": error}, 400

    # Authorization check — always verify when user context is available
    if user_id:
        from src.settings.team_access import can_review_repository, user_has_repository_access
        from src.settings.organisations_store import list_teams
        from src.settings.direct_access_store import list_direct_grants

        teams = list_teams()
        direct_grants = list_direct_grants()

        for update in (normalized_updates or []):
            repo = update.get("repository")
            if not repo:
                continue
            is_member = user_has_repository_access(teams, user_id, org, repo, direct_grants=direct_grants)
            if not can_review_repository(user_role, is_member, user_role_id=user_role_id):
                return {"error": f"You do not have permission to review findings in {org}/{repo}."}, 403

    # Apply each update via shared lifecycle
    from src.shared.lifecycle import dismiss_finding, reopen_finding
    from src.shared.finding_queries import set_secret_review_status

    now_iso = datetime.now(timezone.utc).isoformat()

    for update in (normalized_updates or []):
        identity_key = update.get("secretIdentity") or update.get("fingerprint") or ""
        if not identity_key:
            continue
        status = update.get("status", "new")
        if status in ("false_positive", "action_taken"):
            reason = "Alert is inaccurate" if status == "false_positive" else "Fix started"
            dismiss_finding("secrets", identity_key, reason, user_id or "unknown", org=org)
        elif status in ("new", "confirmed"):
            reopen_finding("secrets", identity_key, user_id or "unknown", org=org)
        set_secret_review_status(org, identity_key, status)

    # Return fresh snapshot with resolution timestamps applied
    snapshot = read_secrets_snapshot(org)
    if snapshot and "findings" in snapshot:
        fingerprint_to_new_status: dict[str, str] = {}
        for update in (normalized_updates or []):
            fp = update.get("fingerprint", "")
            if fp:
                fingerprint_to_new_status[fp] = update.get("status", "new")

        updated_findings = []
        for finding in snapshot["findings"]:
            fp = str(finding.get("fingerprint") or "")
            if fp in fingerprint_to_new_status:
                new_status = fingerprint_to_new_status[fp]
                old_status = str(finding.get("reviewStatus") or "new")
                finding = _stamp_resolution_timestamps(finding, old_status, new_status, now_iso)
                finding["reviewStatus"] = new_status
            updated_findings.append(finding)
        snapshot["findings"] = updated_findings

    return {"ok": True, "snapshot": snapshot}, 200
