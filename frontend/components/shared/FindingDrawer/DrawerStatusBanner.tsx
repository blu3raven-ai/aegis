// components/shared/FindingDrawer/DrawerStatusBanner.tsx

import { Button } from "@/components/ui/Button"

export function DrawerStatusBanner({
  state,
  dismissedReason,
  fixedAt,
  onReopen,
}: {
  state: "open" | "dismissed" | "fixed" | "awaiting_fix" | "deferred"
  dismissedReason?: string
  fixedAt?: string
  onReopen?: () => void
}) {
  if (state === "dismissed") {
    const isAutoDismissed = dismissedReason === "Auto-dismissed by rule"
    return (
      <div className="flex items-center justify-between border-b border-[var(--color-border)] bg-[var(--color-state-dismissed-subtle)] px-5 py-3">
        <div>
          <p className="text-sm font-medium text-[var(--color-state-dismissed)]">Dismissed</p>
          {dismissedReason && (
            <p className="mt-0.5 text-xs text-[var(--color-state-dismissed-muted)]">
              Reason: {dismissedReason}
            </p>
          )}
          {isAutoDismissed && (
            <p className="mt-1 text-xs text-[var(--color-state-dismissed-muted)]">
              Auto-dismissed by rule. Reopen to restore this finding.
            </p>
          )}
        </div>
        {onReopen && (
          <Button
            variant="secondary"
            size="sm"
            onClick={onReopen}
            className="border-[var(--color-state-dismissed-border)] bg-[var(--color-surface-raised)] text-[var(--color-state-dismissed)] hover:border-[var(--color-state-dismissed-border)] hover:bg-[var(--color-surface)]"
          >
            Reopen
          </Button>
        )}
      </div>
    )
  }

  if (state === "deferred") {
    return (
      <div className="border-b border-[var(--color-border)] bg-[var(--color-state-deferred-subtle)] px-5 py-3">
        <p className="text-sm font-medium text-[var(--color-state-deferred)]">
          Deferred: no patch available
        </p>
        <p className="mt-0.5 text-xs text-[var(--color-state-deferred-muted)]">
          Will reopen automatically when a fix is released.
        </p>
      </div>
    )
  }

  if (state === "fixed" && fixedAt) {
    return (
      <div className="border-b border-[var(--color-border)] bg-[var(--color-state-fixed-subtle)] px-5 py-3">
        <p className="text-sm font-medium text-[var(--color-state-fixed)]">Fixed</p>
        <p className="mt-0.5 text-xs text-[var(--color-state-fixed-muted)]">Fixed at: {fixedAt}</p>
      </div>
    )
  }

  return null
}
