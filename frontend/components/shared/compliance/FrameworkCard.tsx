import { type ControlSummaryItem, deriveControlStatus } from "@/lib/client/compliance-api"
import { Button } from "@/components/ui/Button"

interface FrameworkCardProps {
  framework: { id: string; label: string }
  summary: ControlSummaryItem[] | null // null = loading
  error?: boolean // true = error state
  selected: boolean
  onClick: () => void
  onRetry?: () => void // called when user clicks Retry in error state
}

export function FrameworkCard({
  framework,
  summary,
  error = false,
  selected,
  onClick,
  onRetry,
}: FrameworkCardProps) {
  // Derive metrics once — avoid re-computing per-render in JSX
  const derived =
    summary !== null && !error
      ? (() => {
          const total = summary.length
          let met = 0
          let critical = 0
          for (const c of summary) {
            const status = deriveControlStatus(c)
            if (status === "met") met++
            else if (c.highest_severity === "critical") critical++
          }
          const gaps = total - met
          const pct = total > 0 ? met / total : 0
          return { total, met, gaps, critical, pct }
        })()
      : null

  // An empty framework (no controls) stays neutral — never red — so it doesn't
  // read as a critical 0% coverage gap.
  const barColor =
    derived === null || derived.total === 0
      ? "bg-[var(--color-border)]"
      : derived.pct >= 0.95
        ? "bg-[var(--color-status-ok)]"
        : derived.pct >= 0.8
          ? "bg-[var(--color-severity-medium)]"
          : "bg-[var(--color-severity-critical)]"

  const containerClass = [
    "flex flex-col gap-3 rounded-xl border p-5 text-left transition-colors w-full",
    selected
      ? "border-[var(--color-accent)] bg-[var(--color-accent-subtle)]"
      : "border-[var(--color-border)] bg-[var(--color-surface)]",
  ].join(" ")

  const pctValue = derived !== null ? Math.round(derived.pct * 100) : null
  const pctClass =
    derived === null || derived.total === 0
      ? "text-[var(--color-text-secondary)]"
      : derived.pct >= 0.95
        ? "text-[var(--color-status-ok-text)]"
        : derived.pct >= 0.8
          ? "text-[var(--color-severity-medium-text)]"
          : "text-[var(--color-severity-critical-text)]"

  const innerContent = (
    <>
      {/* Head — framework name. Mock's right-side tag (Due Xd / N gaps / Audit YYYY) is deferred
          until the API exposes attestation due dates + scope metadata. */}
      <div>
        <h3 className="text-base font-semibold break-words text-[var(--color-text-primary)]">
          {framework.label}
        </h3>
      </div>

      {/* Progress bar */}
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-[var(--color-border)]">
        {summary === null && !error ? (
          <div className="h-full w-1/2 animate-pulse rounded-full bg-[var(--color-border)]" />
        ) : derived !== null ? (
          <div
            className={`h-full rounded-full transition-all ${barColor}`}
            style={{ width: `${pctValue}%` }}
          />
        ) : null}
      </div>

      {/* Coverage row — prominent % + fraction (mock fw-card-coverage) */}
      {summary === null && !error ? (
        <div className="flex items-baseline gap-2">
          <span className="text-xl font-semibold leading-none text-[var(--color-text-secondary)]">—</span>
          <span className="text-xs text-[var(--color-text-secondary)]">Loading…</span>
        </div>
      ) : error ? (
        <p className="text-xs text-[var(--color-text-secondary)]">
          Could not load
          {onRetry ? (
            <>
              {" · "}
              <Button
                variant="link"
                size="xs"
                onClick={(e) => {
                  e.stopPropagation()
                  onRetry()
                }}
                className="text-[var(--color-accent)] underline-offset-2 hover:underline hover:text-[var(--color-accent)]"
              >
                Retry
              </Button>
            </>
          ) : null}
        </p>
      ) : derived !== null ? (
        <>
          <div className="flex items-baseline gap-2">
            {derived.total === 0 ? (
              <span className="text-sm text-[var(--color-text-secondary)]">No controls yet</span>
            ) : (
              <>
                <span className={`text-xl font-semibold leading-none tabular-nums ${pctClass}`}>
                  {pctValue}%
                </span>
                <span className="text-xs text-[var(--color-text-secondary)]">
                  {derived.met} of {derived.total} controls
                </span>
              </>
            )}
          </div>

          {/* Foot — gaps on left, action on right (mock fw-card-foot) */}
          <div className="mt-auto flex items-center justify-between gap-2 text-xs">
            <span className="text-[var(--color-text-secondary)]">
              {derived.total === 0
                ? null
                : derived.gaps === 0
                  ? "No gaps"
                  : `${derived.gaps} ${derived.gaps === 1 ? "gap" : "gaps"} · ${derived.critical} critical`}
            </span>
            <span className="text-[var(--color-accent)]">{selected ? "Viewing →" : "View controls →"}</span>
          </div>
        </>
      ) : null}
    </>
  )

  // Error state: use a div wrapper so the Retry <button> inside is not a nested button
  if (error) {
    return (
      <div
        role="button"
        tabIndex={0}
        aria-pressed={selected}
        onClick={onClick}
        onKeyDown={(e: React.KeyboardEvent<HTMLDivElement>) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault()
            onClick()
          }
        }}
        className={containerClass}
      >
        {innerContent}
      </div>
    )
  }

  return (
    <button
      type="button"
      aria-pressed={selected}
      onClick={onClick}
      className={containerClass}
    >
      {innerContent}
    </button>
  )
}
