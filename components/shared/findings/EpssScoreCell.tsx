"use client"

import { epssBucket, formatPercentile } from "@/lib/client/epss-api"

interface EpssScoreCellProps {
  /** EPSS percentile in [0.0, 1.0] — null/undefined renders an em-dash. */
  percentile?: number | null
}

const BUCKET_COLOR = {
  high: "var(--color-severity-critical)",
  medium: "var(--color-severity-high)",
} as const

/**
 * Renders an EPSS percentile as a rounded percent with a small colored
 * dot when the rank is high enough to act on. Falls back to an em dash
 * when the underlying CVE has no score in the feed.
 */
export function EpssScoreCell({ percentile }: EpssScoreCellProps) {
  const label = formatPercentile(percentile)
  if (label == null) {
    return (
      <span
        className="text-[var(--color-text-tertiary)] text-xs tabular-nums text-right block"
        aria-label="No EPSS score"
      >
        —
      </span>
    )
  }

  const bucket = epssBucket(percentile)
  return (
    <span
      className="inline-flex items-center gap-1.5 tabular-nums text-xs text-[var(--color-text-primary)]"
      aria-label={`EPSS percentile ${label}`}
    >
      {bucket !== "none" && (
        <span
          className="inline-block h-1.5 w-1.5 rounded-full"
          style={{ background: BUCKET_COLOR[bucket] }}
          aria-hidden="true"
        />
      )}
      {label}
    </span>
  )
}
