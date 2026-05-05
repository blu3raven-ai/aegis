import type { SecretsTrendEntry } from "@/lib/shared/secrets/types"

interface Step {
  label: string
  delta: number
  tone: "neutral" | "up" | "down"
}

function latestDelta(trend: SecretsTrendEntry[]) {
  const latest = trend.at(-1)
  const previous = trend.at(-2)
  if (!latest) return null

  const startingBacklog = previous?.endOfMonth.unresolved ?? 0
  const newlyDetected = latest.newlyDetected
  const endingBacklog = latest.endOfMonth.unresolved

  // Derive net reduction from the accounting equation so it always balances:
  // startingBacklog + newlyDetected - totalRemoved = endingBacklog
  const totalRemoved = Math.max(0, startingBacklog + newlyDetected - endingBacklog)

  // resolved is the only per-period count we trust (action_taken + confirmed resolved)
  // false-positive cumulative snapshots are unreliable for period deltas, so we
  // show "other" for any removal that isn't explicitly resolved.
  const resolved = Math.min(latest.resolved, totalRemoved)
  const otherRemoved = totalRemoved - resolved

  return { startingBacklog, newlyDetected, resolved, otherRemoved, totalRemoved, endingBacklog, month: latest.month }
}

export function BacklogChangeWaterfallChart({ trend }: { trend: SecretsTrendEntry[] }) {
  const latest = latestDelta(trend)
  if (!latest) {
    return <div className="rounded-2xl border border-dashed border-[var(--color-border)] p-6 text-sm text-[var(--color-text-secondary)]">Not enough trend data to display yet.</div>
  }

  const steps: Step[] = [
    { label: "Starting backlog", delta: latest.startingBacklog, tone: "neutral" },
    { label: "Newly detected", delta: latest.newlyDetected, tone: "up" },
    { label: "Resolved", delta: -latest.resolved, tone: "down" },
    { label: "Noise / FP", delta: -latest.otherRemoved, tone: "down" },
    { label: "Ending backlog", delta: latest.endingBacklog, tone: "neutral" },
  ]

  return (
    <div className="rounded-3xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-5">
      <p className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">Period Change</p>
      <h3 className="mt-2 text-2xl font-semibold text-[var(--color-text-primary)]">What changed this period</h3>
      <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
        Where backlog started, what pushed it up, what pulled it down, and where it ended.
      </p>

      <div className="mt-5 space-y-4">
        <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
          <p className="text-[11px] uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">Starting backlog</p>
          <p className="mt-2 text-3xl font-semibold text-[var(--color-text-primary)]">+{latest.startingBacklog}</p>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-2xl border border-orange-500/20 bg-orange-500/10 p-4">
            <p className="text-[11px] uppercase tracking-[0.22em] text-orange-200">Increased backlog</p>
            <p className="mt-2 text-3xl font-semibold text-orange-100">+{latest.newlyDetected}</p>
            <p className="mt-2 text-sm text-orange-100/80">Newly detected secrets added this period</p>
          </div>
          <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/10 p-4">
            <p className="text-[11px] uppercase tracking-[0.22em] text-emerald-200">Reduced backlog</p>
            <p className="mt-2 text-3xl font-semibold text-emerald-100">
              -{latest.resolved + latest.otherRemoved}
            </p>
            <p className="mt-2 text-sm text-emerald-100/80">
              {latest.resolved} resolved and {latest.otherRemoved} marked as noise
            </p>
          </div>
        </div>

        <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
          <p className="text-[11px] uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">Ending backlog</p>
          <p className="mt-2 text-4xl font-semibold text-[var(--color-text-primary)]">+{latest.endingBacklog}</p>
        </div>
      </div>
    </div>
  )
}
