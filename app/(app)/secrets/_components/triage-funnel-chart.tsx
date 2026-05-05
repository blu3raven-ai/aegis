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
        { label: "Newly detected this period", value: newlyDetected, color: "bg-blue-500/20 text-blue-600 border-blue-500/50" },
        { label: `Triaged (${resolved} rotated · ${fpDelta} marked FP)`, value: reviewed, color: "bg-amber-500/20 text-amber-600 border-amber-500/50" },
        { label: "Rotated / remediated", value: resolved, color: "bg-emerald-500/20 text-emerald-600 border-emerald-500/50" },
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
