"""Rule 4: Lifecycle — file deletion → close findings for that file.

When a commit deletes a file, any open findings whose detail.file_path matches
are closed automatically. This avoids stale findings for code that no longer
exists.

Triggers on code.push (batch of file changes from a git push).
"""
from __future__ import annotations

import logging

from src.correlation.rule import Rule, RuleContext

logger = logging.getLogger(__name__)


class LifecycleRule:
    """Rule 4: Lifecycle (file deletion)."""

    triggers: list[str] = ["code.push"]
    name: str = "lifecycle"

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        payload = event.get("payload", {})
        org_id = event.get("org_id", "")
        repo = payload.get("repo_id") or payload.get("repo")

        if not repo or not org_id:
            return

        # Deleted files are carried in the push payload as a list of paths
        deleted_files: list[str] = payload.get("deleted_files") or []
        if not deleted_files:
            return

        for file_path in deleted_files:
            self._close_findings_for_file(event, org_id, repo, file_path, ctx)

    def _close_findings_for_file(
        self,
        event: dict,
        org_id: str,
        repo: str,
        file_path: str,
        ctx: RuleContext,
    ) -> None:
        open_findings = ctx.state.lookup_open_findings(
            org_id=org_id,
            repo_id=repo,
            file_path=file_path,
        )
        for finding in open_findings:
            ctx.emit.emit_close(
                finding["id"],
                reason=f"source file deleted: {file_path}",
                rule_name=self.name,
            )
            logger.info(
                "lifecycle: closed finding %d — file deleted: %s",
                finding["id"], file_path,
            )
