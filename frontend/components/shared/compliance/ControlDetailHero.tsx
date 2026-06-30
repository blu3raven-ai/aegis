import { ControlBadge } from "./ControlBadge"
import { Card } from "@/components/ui/Card"

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-[var(--color-severity-critical)]",
  high: "text-[var(--color-severity-high)]",
  medium: "text-[var(--color-severity-medium)]",
  low: "text-[var(--color-severity-low)]",
}

interface ControlDetailHeroProps {
  framework: string
  controlId: string
  title: string
  description?: string | null
  category?: string | null
  findingCount: number
  highestSeverity?: string | null
}

export function ControlDetailHero({
  framework,
  controlId,
  title,
  description,
  category,
  findingCount,
  highestSeverity,
}: ControlDetailHeroProps) {
  const atRisk = findingCount > 0

  return (
    <Card padding="lg" elevation="sm" className="rounded-xl">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-2">
            <ControlBadge framework={framework} controlId={controlId} />
            {category && (
              <span className="text-[11px] text-[var(--color-text-secondary)]">{category}</span>
            )}
          </div>
          <h1 className="text-lg font-semibold tracking-tight text-[var(--color-text-primary)]">{title}</h1>
          {description && (
            <p className="max-w-2xl text-sm leading-relaxed text-[var(--color-text-secondary)]">
              {description}
            </p>
          )}
        </div>

        {/* Status badge */}
        <div className="shrink-0">
          {atRisk ? (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-3 py-1 text-xs font-semibold text-[var(--color-severity-critical)]">
              <span className="h-2 w-2 rounded-full bg-[var(--color-severity-critical)]" />
              At Risk
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--color-status-ok-border)] bg-[var(--color-status-ok-subtle)] px-3 py-1 text-xs font-semibold text-[var(--color-status-ok)]">
              <span className="h-2 w-2 rounded-full bg-[var(--color-status-ok)]" />
              Compliant
            </span>
          )}
        </div>
      </div>

      {/* Metric chips */}
      <div className="mt-5 flex flex-wrap gap-3">
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-2">
          <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
            Open Findings
          </div>
          <div
            className={`mt-0.5 text-2xl font-semibold leading-none tabular-nums ${findingCount > 0 ? "text-[var(--color-severity-critical)]" : "text-[var(--color-text-primary)]"}`}
          >
            {findingCount}
          </div>
        </div>

        {highestSeverity && (
          <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-2">
            <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
              Highest Severity
            </div>
            <div
              className={`mt-0.5 text-2xl font-semibold leading-none tabular-nums capitalize ${SEVERITY_COLORS[highestSeverity] ?? "text-[var(--color-text-primary)]"}`}
            >
              {highestSeverity}
            </div>
          </div>
        )}
      </div>
    </Card>
  )
}
