// components/shared/FindingDrawer/DrawerStatusBanner.tsx

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
    return (
      <div className="flex items-center justify-between border-b border-[var(--color-border)] bg-purple-500/5 px-5 py-3">
        <div>
          <p className="text-sm font-medium text-purple-400">Dismissed</p>
          {dismissedReason && (
            <p className="mt-0.5 text-xs text-purple-400/70">
              Reason: {dismissedReason}
            </p>
          )}
        </div>
        {onReopen && (
          <button
            type="button"
            onClick={onReopen}
            className="rounded-lg border border-purple-500/30 bg-[var(--color-surface-raised)] px-3 py-1.5 text-xs font-semibold text-purple-400 hover:bg-[var(--color-surface)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
          >
            Reopen
          </button>
        )}
      </div>
    )
  }

  if (state === "deferred") {
    return (
      <div className="border-b border-[var(--color-border)] bg-orange-500/5 px-5 py-3">
        <p className="text-sm font-medium text-orange-400">
          Deferred: no patch available
        </p>
        <p className="mt-0.5 text-xs text-orange-400/70">
          Will reopen automatically when a fix is released.
        </p>
      </div>
    )
  }

  if (state === "fixed" && fixedAt) {
    return (
      <div className="border-b border-[var(--color-border)] bg-emerald-500/5 px-5 py-3">
        <p className="text-sm font-medium text-emerald-400">Fixed</p>
        <p className="mt-0.5 text-xs text-emerald-400/70">Fixed at: {fixedAt}</p>
      </div>
    )
  }

  return null
}
