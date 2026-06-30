// components/shared/FindingDrawer/DrawerStatusBanner.tsx

export function DrawerStatusBanner({
  state,
  dismissedReason,
  fixedAt,
}: {
  state: string
  dismissedReason?: string
  fixedAt?: string
}) {
  if (state === "dismissed") {
    return (
      <div className="border-b border-[var(--color-border)] bg-[var(--color-state-dismissed-subtle)] px-5 py-3">
        <p className="text-sm font-medium text-[var(--color-state-dismissed)]">Dismissed</p>
        {dismissedReason && (
          <p className="mt-0.5 text-xs text-[var(--color-state-dismissed-muted)]">
            Reason: {dismissedReason}
          </p>
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

  if (state === "fixed" || state === "closed") {
    return (
      <div className="border-b border-[var(--color-border)] bg-[var(--color-state-fixed-subtle)] px-5 py-3">
        <p className="text-sm font-medium text-[var(--color-state-fixed)]">
          {state === "fixed" ? "Fixed" : "Closed"}
        </p>
        {fixedAt && (
          <p className="mt-0.5 text-xs text-[var(--color-state-fixed-muted)]">Fixed at: {fixedAt}</p>
        )}
      </div>
    )
  }

  return null
}
