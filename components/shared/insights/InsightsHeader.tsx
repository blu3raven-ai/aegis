"use client"

import { PageHeader } from "@/components/layout/PageHeader"
import { InsightsIcon } from "@/lib/shared/ui/page-icons"

const WINDOW_OPTIONS = [
  { label: "7d", value: 7 },
  { label: "30d", value: 30 },
  { label: "90d", value: 90 },
] as const

const SEVERITY_OPTIONS = [
  { label: "All", value: "all" },
  { label: "Critical", value: "critical" },
  { label: "High", value: "high" },
  { label: "Medium", value: "medium" },
  { label: "Low", value: "low" },
] as const

export type WindowDays = (typeof WINDOW_OPTIONS)[number]["value"]
export type SeverityFilter = (typeof SEVERITY_OPTIONS)[number]["value"]

interface InsightsHeaderProps {
  windowDays: WindowDays
  severity: SeverityFilter
  onWindowChange: (w: WindowDays) => void
  onSeverityChange: (s: SeverityFilter) => void
}

function ChipGroup<T extends string | number>({
  options,
  value,
  onChange,
  ariaLabel,
}: {
  options: ReadonlyArray<{ label: string; value: T }>
  value: T
  onChange: (v: T) => void
  ariaLabel: string
}) {
  return (
    <div
      className="flex items-center rounded-lg border border-[var(--color-border)] overflow-hidden"
      role="radiogroup"
      aria-label={ariaLabel}
    >
      {options.map((opt, i) => (
        <button
          key={String(opt.value)}
          type="button"
          role="radio"
          aria-checked={value === opt.value}
          onClick={() => onChange(opt.value)}
          className={[
            "px-3 py-1.5 text-xs font-semibold transition-colors",
            i < options.length - 1 ? "border-r border-[var(--color-border)]" : "",
            value === opt.value
              ? "bg-[var(--color-accent)] text-[var(--color-accent-on)]"
              : "bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]",
          ]
            .filter(Boolean)
            .join(" ")}
        >
          {opt.label}
        </button>
      ))}
    </div>
  )
}

export function InsightsHeader({ windowDays, severity, onWindowChange, onSeverityChange }: InsightsHeaderProps) {
  return (
    <>
      <PageHeader
        icon={<InsightsIcon />}
        title="Insights"
        description="Trends, attribution, and remediation velocity across the org."
      />
      <div className="border-b border-[var(--color-border)] bg-[var(--color-surface)] px-5 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <ChipGroup
            options={WINDOW_OPTIONS}
            value={windowDays}
            onChange={onWindowChange}
            ariaLabel="Time window"
          />
          <ChipGroup
            options={SEVERITY_OPTIONS}
            value={severity}
            onChange={onSeverityChange}
            ariaLabel="Filter by severity"
          />
        </div>
      </div>
    </>
  )
}
