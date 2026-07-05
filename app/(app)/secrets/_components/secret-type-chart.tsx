import type { SecretFinding } from "@/lib/shared/secrets/types"

export function SecretTypeChart({
  findings,
  onSelectKeyType,
}: {
  findings: SecretFinding[]
  onSelectKeyType?: (detector: string, status?: string) => void
}) {
  const active = findings.filter(
    (f) => f.reviewStatus === "new" || f.reviewStatus === "confirmed"
  )

  if (active.length === 0) {
    return (
      <div className="flex min-h-40 items-center justify-center rounded-2xl border border-dashed border-[var(--color-border)] text-sm text-[var(--color-text-secondary)]">
        No findings to display.
      </div>
    )
  }

  const byType = new Map<string, { confirmed: number; new: number }>()
  for (const f of active) {
    const entry = byType.get(f.detector) ?? { confirmed: 0, new: 0 }
    if (f.reviewStatus === "confirmed") entry.confirmed++
    else entry.new++
    byType.set(f.detector, entry)
  }

  const rows = Array.from(byType.entries())
    .map(([type, counts]) => ({ type, ...counts, total: counts.confirmed + counts.new }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 12)

  const maxTotal = Math.max(1, ...rows.map((r) => r.total))

  return (
    <div className="flex flex-col" style={{ height: "320px" }}>
      {/* Scrollable list */}
      <div className="min-h-0 flex-1 overflow-y-auto space-y-1.5 pr-1">
        {rows.map((row, i) => (
          <div key={row.type} className="group relative flex items-center gap-3 rounded-xl px-3 py-2.5 transition-colors hover:bg-[var(--color-surface-raised)]">
            {/* Rank */}
            <span className="w-4 shrink-0 text-right text-xs tabular-nums text-[var(--color-text-secondary)] opacity-50">
              {i + 1}
            </span>

            {/* Background proportion fill */}
            <div
              className="pointer-events-none absolute inset-y-1 left-8 rounded-lg opacity-[0.06]"
              style={{
                width: `calc(${(row.total / maxTotal) * 80}%)`,
                backgroundColor: row.confirmed > 0 ? "var(--color-severity-critical)" : "var(--color-severity-high)",
              }}
            />

            {/* Label — click to filter by type (all statuses) */}
            <button
              type="button"
              className="min-w-0 flex-1 truncate text-left text-sm font-medium text-[var(--color-text-primary)] hover:underline disabled:cursor-default disabled:no-underline"
              title={onSelectKeyType ? `Filter review by ${row.type}` : row.type}
              onClick={() => onSelectKeyType?.(row.type)}
              disabled={!onSelectKeyType}
            >
              {row.type}
            </button>

            {/* Count badges — click to filter by type + status */}
            <div className="flex shrink-0 items-center gap-1.5">
              {row.confirmed > 0 && (
                <button
                  type="button"
                  title={onSelectKeyType ? `Show ${row.confirmed} confirmed ${row.type} in Review` : undefined}
                  onClick={(e) => { e.stopPropagation(); onSelectKeyType?.(row.type, "confirmed") }}
                  disabled={!onSelectKeyType}
                  className="flex items-center gap-1 rounded-full border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-2 py-0.5 text-xs font-semibold tabular-nums text-[var(--color-severity-critical)] transition-colors hover:opacity-80 disabled:cursor-default disabled:pointer-events-none"
                >
                  <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-severity-critical)]" />
                  {row.confirmed}
                </button>
              )}
              {row.new > 0 && (
                <button
                  type="button"
                  title={onSelectKeyType ? `Show ${row.new} new ${row.type} in Review` : undefined}
                  onClick={(e) => { e.stopPropagation(); onSelectKeyType?.(row.type, "new") }}
                  disabled={!onSelectKeyType}
                  className="flex items-center gap-1 rounded-full border border-[var(--color-severity-high-border)] bg-[var(--color-severity-high-subtle)] px-2 py-0.5 text-xs font-semibold tabular-nums text-[var(--color-severity-high)] transition-colors hover:opacity-80 disabled:cursor-default disabled:pointer-events-none"
                >
                  <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-severity-high)]" />
                  {row.new}
                </button>
              )}
            </div>

            {/* Total */}
            <span className="w-6 shrink-0 text-right text-xs font-semibold tabular-nums text-[var(--color-text-secondary)]">
              {row.total}
            </span>
          </div>
        ))}
      </div>

      {/* Legend + hint — pinned to bottom */}
      <div className="flex items-center justify-between border-t border-[var(--color-border)] pt-3 mt-2 pl-7">
        <div className="flex gap-4">
          <span className="flex items-center gap-1.5 text-xs text-[var(--color-text-secondary)]">
            <span className="h-2 w-2 rounded-full bg-[var(--color-severity-critical)]" /> Confirmed
          </span>
          <span className="flex items-center gap-1.5 text-xs text-[var(--color-text-secondary)]">
            <span className="h-2 w-2 rounded-full bg-[var(--color-severity-high)]" /> New
          </span>
        </div>
        {onSelectKeyType && (
          <span className="text-xs text-[var(--color-text-secondary)] opacity-60">
            Click a row or badge to filter Review
          </span>
        )}
      </div>
    </div>
  )
}
