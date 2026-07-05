"use client"

interface ResourceGaugeProps {
  label: string
  percent: number | null
  detail?: string
}

function gaugeColor(percent: number): string {
  if (percent >= 90) return "bg-[var(--color-severity-critical)]"
  if (percent >= 70) return "bg-[var(--color-state-pending)]"
  return "bg-[var(--color-status-ok)]"
}

export function ResourceGauge({ label, percent, detail }: ResourceGaugeProps) {
  if (percent == null) {
    return (
      <div className="flex items-center gap-3">
        <span className="w-16 text-xs text-[var(--color-text-secondary)]">{label}</span>
        <span className="text-xs text-[var(--color-text-secondary)]">—</span>
      </div>
    )
  }

  const clamped = Math.max(0, Math.min(100, percent))

  return (
    <div className="flex items-center gap-3">
      <span className="w-16 shrink-0 text-xs font-medium text-[var(--color-text-secondary)]">{label}</span>
      <div className="flex-1 h-2 rounded-full bg-[var(--color-border-strong)] overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-300 ${gaugeColor(clamped)}`}
          style={{ width: `${clamped}%` }}
        />
      </div>
      <span className="w-12 shrink-0 text-right text-xs tabular-nums text-[var(--color-text-secondary)]">
        {Math.round(clamped)}%
      </span>
      {detail && (
        <span className="hidden sm:block w-24 shrink-0 text-right text-xs text-[var(--color-text-secondary)]">
          {detail}
        </span>
      )}
    </div>
  )
}
