"use client"

import type { GqlCodeScanningAnalytics } from "@/lib/shared/graphql/types"

const SEV_COLOURS: Record<string, string> = {
  critical: "bg-[var(--color-severity-critical)]",
  high: "bg-[var(--color-severity-high)]",
  medium: "bg-[var(--color-severity-medium)]",
  low: "bg-[var(--color-severity-low)]",
}

const STATE_COLOURS: Record<string, string> = {
  open: "bg-[var(--color-status-ok)]",
  dismissed: "bg-[var(--color-state-dismissed)]",
  fixed: "bg-[var(--color-state-fixed)]",
  awaiting_fix: "bg-[var(--color-state-pending)]",
}

const STATE_LABELS: Record<string, string> = {
  open: "Open",
  dismissed: "Dismissed",
  fixed: "Fixed",
  awaiting_fix: "Awaiting Fix",
}

function HorizontalBarRow({
  label,
  count,
  total,
  colourClass,
  onClick,
}: {
  label: string
  count: number
  total: number
  colourClass: string
  onClick?: () => void
}) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0
  const Tag = onClick ? "button" : "div"
  return (
    <Tag
      type={onClick ? "button" : undefined}
      onClick={onClick}
      className={`flex w-full items-center gap-3 rounded-lg px-1 py-0.5 text-left ${onClick ? "transition-colors hover:bg-[var(--color-surface-raised)] cursor-pointer" : ""}`}
    >
      <span className="w-24 shrink-0 truncate text-right text-xs text-[var(--color-text-secondary)]">{label}</span>
      <div className="flex flex-1 overflow-hidden rounded-full bg-[var(--color-border)]" style={{ height: 10 }}>
        <div className={`h-full rounded-full ${colourClass}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="w-8 text-right text-xs font-semibold text-[var(--color-text-primary)]">{count}</span>
    </Tag>
  )
}

export function InsightsExposureBreakdown({
  analytics,
  onGoToFindings,
}: {
  analytics: GqlCodeScanningAnalytics | null
  onGoToFindings: (opts: { severity?: string; state?: string }) => void
}) {
  const counts = analytics?.counts ?? { total: 0, critical: 0, high: 0, medium: 0, low: 0 }
  const sb = analytics?.stateBreakdown ?? { open: 0, dismissed: 0, fixed: 0, awaitingFix: 0 }
  const totalAll = sb.open + sb.dismissed + sb.fixed + sb.awaitingFix

  const stateCounts = {
    open: sb.open,
    dismissed: sb.dismissed,
    fixed: sb.fixed,
    awaiting_fix: sb.awaitingFix,
  }

  return (
    <section className="space-y-6">
      <div className="border-t border-[var(--color-border)] pt-12">
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">Exposure Breakdown</h2>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          What is the current severity and state of all findings?
        </p>
      </div>

      {/* KPI strip */}
      <div className="grid gap-4 sm:grid-cols-5">
        {[
          { label: "Total", value: totalAll, colour: "text-[var(--color-text-primary)]", note: "All findings" },
          { label: "Open", value: sb.open, colour: "text-[var(--color-status-ok)]", note: "Needs attention" },
          { label: "Dismissed", value: sb.dismissed, colour: "text-[var(--color-text-secondary)]", note: "Reviewed" },
          { label: "Fixed", value: sb.fixed, colour: "text-[var(--color-state-fixed)]", note: "Resolved" },
          { label: "Awaiting Fix", value: sb.awaitingFix, colour: "text-[var(--color-state-pending)]", note: "Fix in progress" },
        ].map(({ label, value, colour, note }) => (
          <div
            key={label}
            className="flex flex-col rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-4 shadow-[0_28px_80px_rgba(15,23,42,0.06)]"
          >
            <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">{label}</p>
            <p className={`mt-3 text-2xl font-semibold leading-none tabular-nums ${colour}`}>{value}</p>
            <p className="mt-2 text-sm text-[var(--color-text-secondary)]">{note}</p>
          </div>
        ))}
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        {/* Severity distribution — open findings only */}
        <div className="rounded-[20px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
          <p className="mb-4 text-sm font-semibold text-[var(--color-text-primary)]">
            Open findings by severity
          </p>
          <div className="space-y-2">
            {(["critical", "high", "medium", "low"] as const).map((sev) => (
              <HorizontalBarRow
                key={sev}
                label={sev.charAt(0).toUpperCase() + sev.slice(1)}
                count={counts[sev]}
                total={counts.total}
                colourClass={SEV_COLOURS[sev]}
                onClick={() => onGoToFindings({ severity: sev })}
              />
            ))}
          </div>
          <p className="mt-3 text-[11px] text-[var(--color-text-secondary)]">Click a row to filter findings by severity.</p>
        </div>

        {/* State distribution — clickable */}
        <div className="rounded-[20px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
          <p className="mb-4 text-sm font-semibold text-[var(--color-text-primary)]">
            Findings by state
          </p>
          <div className="space-y-2">
            {(["open", "dismissed", "fixed", "awaiting_fix"] as const).map((state) => (
              <HorizontalBarRow
                key={state}
                label={STATE_LABELS[state]}
                count={stateCounts[state]}
                total={totalAll}
                colourClass={STATE_COLOURS[state]}
                onClick={() => onGoToFindings({ state })}
              />
            ))}
          </div>
          <p className="mt-3 text-[11px] text-[var(--color-text-secondary)]">Click a row to filter findings by state.</p>
        </div>
      </div>
    </section>
  )
}
