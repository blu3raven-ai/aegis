import type { SecretsOverviewFilterOpts } from "@/app/(app)/secrets/_components/overview-kpi-strip"

const STATUSES = [
  { key: "new", label: "New", note: "Awaiting triage", tone: "bg-[var(--color-severity-high)]", textTone: "text-[var(--color-severity-high)]" },
  { key: "confirmed", label: "Confirmed", note: "Needs rotation", tone: "bg-[var(--color-severity-critical)]", textTone: "text-[var(--color-severity-critical)]" },
  { key: "false_positive", label: "False Positive", note: "Reviewed as safe", tone: "bg-[var(--color-status-ok)]", textTone: "text-[var(--color-status-ok)]" },
  { key: "action_taken", label: "Action Taken", note: "Rotated or revoked", tone: "bg-[var(--color-accent)]", textTone: "text-[var(--color-accent)]" },
] as const

export function OverviewReviewFocus({
  funnel,
  onOpenReviewFiltered,
}: {
  funnel: {
    newCount: number
    confirmedCount: number
    falsePositiveCount: number
    actionTakenCount: number
  }
  onOpenReviewFiltered: (opts: SecretsOverviewFilterOpts) => void
}) {
  const total = funnel.newCount + funnel.confirmedCount + funnel.falsePositiveCount + funnel.actionTakenCount
  const counts: Record<string, number> = {
    new: funnel.newCount,
    confirmed: funnel.confirmedCount,
    false_positive: funnel.falsePositiveCount,
    action_taken: funnel.actionTakenCount,
  }

  return (
    <>
      <div className="mb-4 flex items-center justify-between gap-3">
        <h3 className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">
          Review Focus
        </h3>
        <button
          type="button"
          onClick={() => onOpenReviewFiltered({})}
          className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-1 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)]"
        >
          {total} total
        </button>
      </div>

      {/* Stacked progress bar */}
      <div className="h-3 overflow-hidden rounded-full bg-[var(--color-border)]">
        <div className="flex h-full">
          {total > 0 && STATUSES.map((s) => {
            const count = counts[s.key]
            if (count === 0) return null
            return <div key={s.key} className={s.tone} style={{ width: `${(count / total) * 100}%` }} />
          })}
        </div>
      </div>

      {/* Status cards */}
      <div className="mt-4 space-y-2">
        {STATUSES.map((s) => {
          const count = counts[s.key]
          const pct = total > 0 ? Math.round((count / total) * 100) : 0
          return (
            <button
              key={s.key}
              type="button"
              onClick={() => onOpenReviewFiltered({ status: s.key })}
              className="w-full text-left transition-colors"
            >
              <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-3">
                <div className="mb-2 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <span className={`h-2.5 w-2.5 rounded-full ${s.tone}`} />
                    <span className="text-sm font-medium text-[var(--color-text-primary)]">{s.label}</span>
                  </div>
                  <span className="text-sm text-[var(--color-text-secondary)]">{pct}%</span>
                </div>
                <div className="h-2.5 rounded-full bg-[var(--color-surface-raised)]">
                  <div className={`h-2.5 rounded-full ${s.tone}`} style={{ width: `${Math.max(pct, pct ? 6 : 0)}%` }} />
                </div>
                <div className="mt-2 flex items-center justify-between text-xs text-[var(--color-text-secondary)]">
                  <span>{count} keys</span>
                  <span>{s.note}</span>
                </div>
              </div>
            </button>
          )
        })}
      </div>

      <button
        type="button"
        onClick={() => onOpenReviewFiltered({})}
        className="mt-5 flex w-full items-center justify-between rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3 text-left transition-colors hover:border-[var(--color-accent-border)]"
      >
        <span className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
          View all in Review
        </span>
        <span className="text-xs text-[var(--color-accent)]">→</span>
      </button>
    </>
  )
}
