"use client"

import Link from "next/link"
import type { EpssTopFinding } from "@/lib/client/epss-api"
import { formatPercentile, epssBucket } from "@/lib/client/epss-api"
import { Card } from "@/components/ui/Card"

interface EpssExposureWidgetProps {
  findings: EpssTopFinding[]
}

const BUCKET_TEXT = {
  high: "text-[var(--color-severity-critical-text)]",
  medium: "text-[var(--color-severity-high-text)]",
  none: "text-[var(--color-text-secondary)]",
} as const

const LINK_FOCUS =
  "focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none focus-visible:rounded-lg"

/**
 * Top open findings ranked by EPSS percentile. Empty state nudges the
 * operator to seed the feed via `aegis epss refresh` (or the daily job).
 */
export function EpssExposureWidget({ findings }: EpssExposureWidgetProps) {
  const hasData = findings.length > 0

  return (
    <Card className="rounded-md">
      <div className="flex items-start justify-between gap-4">
        <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
          EPSS Exposure
        </p>
        {hasData && (
          <span className="shrink-0 text-[11px] text-[var(--color-text-tertiary)]">
            Top {findings.length}
          </span>
        )}
      </div>

      {hasData ? (
        <ul className="mt-4 space-y-2">
          {findings.map((f) => {
            const bucket = epssBucket(f.epss_percentile)
            const label = formatPercentile(f.epss_percentile) ?? "—"
            return (
              <li key={f.finding_id}>
                <Link
                  href={`/findings?finding=${f.finding_id}`}
                  className={`group flex items-center gap-3 rounded-lg px-2 py-1.5 -mx-2 transition-colors hover:bg-[var(--color-bg-hover)] ${LINK_FOCUS}`}
                >
                  <span className="font-[family-name:var(--font-jetbrains-mono)] text-[11.5px] text-[var(--color-text-primary)] shrink-0">
                    {f.cve}
                  </span>
                  <span className="flex-1 truncate text-xs text-[var(--color-text-secondary)]" title={f.repo}>
                    {f.repo}
                  </span>
                  <span className={`tabular-nums text-xs font-semibold shrink-0 ${BUCKET_TEXT[bucket]}`}>
                    {label}
                  </span>
                </Link>
              </li>
            )
          })}
        </ul>
      ) : (
        <p className="mt-4 text-xs text-[var(--color-text-secondary)]">
          No EPSS scores yet. Run{" "}
          <code className="font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-primary)]">
            aegis epss refresh
          </code>{" "}
          or wait for the daily job.
        </p>
      )}
    </Card>
  )
}
