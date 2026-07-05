"use client"

import Link from "next/link"
import type { SlaBreachSummary } from "@/lib/client/sla-api"

type Severity = "critical" | "high" | "medium" | "low"

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low"]

const SEV_COLORS = {
  critical: {
    text: "text-[var(--color-severity-critical)]",
    bar: "bg-[var(--color-severity-critical)]",
    badge: "bg-[var(--color-severity-critical)]/10 text-[var(--color-severity-critical)]",
  },
  high: {
    text: "text-[var(--color-severity-high)]",
    bar: "bg-[var(--color-severity-high)]",
    badge: "bg-[var(--color-severity-high)]/10 text-[var(--color-severity-high)]",
  },
  medium: {
    text: "text-[var(--color-severity-medium)]",
    bar: "bg-[var(--color-severity-medium)]",
    badge: "bg-[var(--color-severity-medium)]/10 text-[var(--color-severity-medium)]",
  },
  low: {
    text: "text-[var(--color-severity-low)]",
    bar: "bg-[var(--color-severity-low)]",
    badge: "bg-[var(--color-severity-low)]/10 text-[var(--color-severity-low)]",
  },
}

interface SlaBreachWidgetProps {
  summary: SlaBreachSummary
  /** href base for findings filtered by SLA breach — severity appended as query param */
  findingsHref?: string
}

export function SlaBreachWidget({ summary, findingsHref = "/findings" }: SlaBreachWidgetProps) {
  const totalBreached = SEV_ORDER.reduce((sum, sev) => sum + (summary[sev]?.breached ?? 0), 0)

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <div className="flex items-start justify-between gap-4">
        <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
          SLA Breach Status
        </p>
        {totalBreached > 0 && (
          <span className="shrink-0 rounded-full bg-[var(--color-severity-critical)]/10 px-2 py-0.5 text-[11px] font-semibold text-[var(--color-severity-critical)]">
            {totalBreached} breached
          </span>
        )}
      </div>

      <div className="mt-4 space-y-3">
        {SEV_ORDER.map((sev) => {
          const stat = summary[sev]
          const open = stat?.open ?? 0
          const breached = stat?.breached ?? 0
          const pct = stat?.breached_pct ?? 0
          const colors = SEV_COLORS[sev]

          return (
            <Link
              key={sev}
              href={`${findingsHref}?sla_breached=true&severity=${sev}`}
              className="group block focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:rounded-lg"
              aria-label={`${sev}: ${breached} of ${open} open findings breached SLA`}
            >
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  <span className={`text-xs font-semibold capitalize ${colors.text}`}>{sev}</span>
                  <span className="text-[11px] text-[var(--color-text-tertiary)]">{open} open</span>
                </div>
                <div className="flex items-center gap-2">
                  {breached > 0 && (
                    <span className={`text-[11px] font-semibold tabular-nums ${colors.text}`}>
                      {breached} breached
                    </span>
                  )}
                  <span className="text-[11px] tabular-nums text-[var(--color-text-tertiary)]">
                    {Math.round(pct * 100)}%
                  </span>
                  <svg
                    className="h-3 w-3 text-[var(--color-text-tertiary)] transition-transform group-hover:translate-x-0.5"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth={2}
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <path d="M9 18l6-6-6-6" />
                  </svg>
                </div>
              </div>
              {open > 0 ? (
                <div className="flex h-1.5 overflow-hidden rounded-full bg-[var(--color-surface-raised)]">
                  {breached > 0 && (
                    <span
                      className={`h-full ${colors.bar}`}
                      style={{ width: `${pct * 100}%` }}
                    />
                  )}
                  {open > breached && (
                    <span
                      className="h-full bg-[var(--color-border)]"
                      style={{ width: `${((open - breached) / open) * 100}%` }}
                    />
                  )}
                </div>
              ) : (
                <div className="h-1.5 rounded-full bg-[var(--color-surface-raised)]" />
              )}
            </Link>
          )
        })}
      </div>

      <Link
        href="/policies?category=sla"
        className="mt-4 block text-[11px] text-[var(--color-text-tertiary)] transition-colors hover:text-[var(--color-accent)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:rounded"
      >
        Manage SLA policies →
      </Link>
    </div>
  )
}
