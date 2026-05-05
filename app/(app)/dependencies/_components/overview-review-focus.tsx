import type { AnalyticsPayload } from "@/lib/shared/dashboard-analytics"
import type { OpenFindingsFilterOpts } from "@/lib/shared/dependencies/utils"

const SEV_META: Record<string, { tone: string; note: string }> = {
  critical: { tone: "bg-red-500",    note: "Could cause serious impact" },
  high:     { tone: "bg-orange-500", note: "Needs attention soon" },
  medium:   { tone: "bg-amber-400",  note: "Plan into upcoming work" },
  low:      { tone: "bg-blue-400",   note: "Lower business impact" },
}

function BreakdownRow({
  label,
  count,
  percentage,
  tone,
  note,
}: {
  label: string
  count: string
  percentage: number
  tone: string
  note: string
}) {
  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-3">
      <div className="mb-2 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className={`h-2.5 w-2.5 rounded-full ${tone}`} />
          <span className="text-sm font-medium text-[var(--color-text-primary)]">{label}</span>
        </div>
        <span className="text-sm text-[var(--color-text-secondary)]">{percentage}%</span>
      </div>
      <div className="h-2.5 rounded-full bg-[var(--color-surface-raised)]">
        <div
          className={`h-2.5 rounded-full ${tone}`}
          style={{ width: `${Math.max(percentage, percentage ? 6 : 0)}%` }}
        />
      </div>
      <div className="mt-2 flex items-center justify-between text-xs text-[var(--color-text-secondary)]">
        <span>{count}</span>
        <span>{note}</span>
      </div>
    </div>
  )
}

export function OverviewReviewFocus({
  analytics,
  activeSeverity,
  onOpenFindingsFiltered,
}: {
  analytics: AnalyticsPayload | null
  activeSeverity: string
  onOpenFindingsFiltered: (opts: OpenFindingsFilterOpts) => void
}) {
  const counts = analytics?.counts
  const severityDistribution = analytics?.severityDistribution ?? []

  return (
    <div>
      {/* Header */}
      <div className="mb-4 flex items-center justify-between gap-3">
        <h3 className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">
          Review Focus
        </h3>
        <button
          type="button"
          onClick={() => onOpenFindingsFiltered({ state: "open" })}
          className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-1 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)]"
        >
          {analytics?.counts.total ?? 0} open
        </button>
      </div>

      {/* Stacked severity bar */}
      {severityDistribution.length > 0 && (
        <div className="flex h-3 overflow-hidden rounded-full bg-[var(--color-border)]">
          {severityDistribution.map((item) => (
            <button
              key={item.severity}
              type="button"
              onClick={() => onOpenFindingsFiltered({ state: "open", severity: [item.severity] })}
              title={`Filter to ${item.severity} findings`}
              className={`transition-opacity hover:opacity-80 ${SEV_META[item.severity]?.tone ?? ""}`}
              style={{ width: `${Math.max(item.percentage, item.count ? 1 : 0)}%` }}
            />
          ))}
        </div>
      )}

      {/* BreakdownRow rows */}
      {severityDistribution.length > 0 && (
        <div className="mt-4 space-y-2">
          {severityDistribution.map((item) => {
            const meta = SEV_META[item.severity]
            if (!meta) return null
            const isActive = activeSeverity === item.severity
            return (
              <button
                key={item.severity}
                type="button"
                onClick={() => onOpenFindingsFiltered({ state: "open", severity: [item.severity] })}
                className={`w-full text-left transition-all ${isActive ? "scale-[1.02] shadow-sm" : ""}`}
              >
                <BreakdownRow
                  label={item.severity.charAt(0).toUpperCase() + item.severity.slice(1)}
                  count={`${item.count} issues`}
                  percentage={item.percentage}
                  tone={meta.tone}
                  note={isActive ? "Filtered ✓" : meta.note}
                />
              </button>
            )
          })}

          <button
            type="button"
            onClick={() => onOpenFindingsFiltered({ state: "dismissed" })}
            className="group flex w-full items-center justify-between rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3 text-left transition-colors hover:border-[var(--color-border)]"
          >
            <span className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)] group-hover:text-[var(--color-text-primary)]">
              View dismissed findings
            </span>
            <span className="text-xs text-[var(--color-accent)]">→</span>
          </button>
        </div>
      )}
    </div>
  )
}
