import type { SecretsTrendEntry } from "@/lib/shared/secrets/types"

export function TriageFunnelChart({ trend }: { trend: SecretsTrendEntry[] }) {
  const latest = trend.at(-1)
  if (!latest) return <div className="rounded-2xl border border-dashed border-[var(--color-border)] p-6 text-sm text-[var(--color-text-secondary)]">No triage data to display yet.</div>

  const previous = trend.at(-2)

  const newlyDetected = latest.newlyDetected
  const resolved = latest.resolved
  // Derive period-safe FP delta — endOfMonth.falsePositive is cumulative, not per-period
  const fpDelta = Math.max(0, (latest.endOfMonth.falsePositive ?? 0) - (previous?.endOfMonth.falsePositive ?? 0))
  const reviewed = resolved + fpDelta

  const max = Math.max(newlyDetected, reviewed, resolved) || 1

  return (
    <div className="space-y-4">
      {[
        { label: "Newly detected this period", value: newlyDetected, color: "bg-[var(--color-severity-low-subtle)] text-[var(--color-severity-low)] border-[var(--color-severity-low-border)]" },
        { label: `Triaged (${resolved} rotated · ${fpDelta} marked FP)`, value: reviewed, color: "bg-[var(--color-severity-medium-subtle)] text-[var(--color-severity-medium)] border-[var(--color-severity-medium-border)]" },
        { label: "Rotated / remediated", value: resolved, color: "bg-[var(--color-status-ok-subtle)] text-[var(--color-status-ok)] border-[var(--color-status-ok-border)]" },
      ].map((step) => (
        <div key={step.label} className="group relative">
          <div className="mb-1 flex items-center justify-between text-xs font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
            <span>{step.label}</span>
            <span>{step.value}</span>
          </div>
          <div className="relative h-10 overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)]">
            <div
              className={`h-full border-r transition-all ${step.color}`}
              style={{ width: `${(step.value / max) * 100}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  )
}
