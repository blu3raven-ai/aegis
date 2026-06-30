"use client"

const NEW_WINDOW_DAYS = 7

export interface FindingRowTagsProps {
  kev?: boolean
  epssPercentile?: number
  firstSeen?: string
}

function isNew(firstSeen: string | undefined): boolean {
  if (!firstSeen) return false
  const seen = new Date(firstSeen).getTime()
  if (Number.isNaN(seen)) return false
  const ageDays = (Date.now() - seen) / (1000 * 60 * 60 * 24)
  return ageDays <= NEW_WINDOW_DAYS
}

export function FindingRowTags({ kev, epssPercentile, firstSeen }: FindingRowTagsProps) {
  const showEpss = typeof epssPercentile === "number" && epssPercentile >= 0.5
  const showNew = isNew(firstSeen)
  if (!kev && !showEpss && !showNew) return null

  return (
    <span className="inline-flex items-center gap-1">
      {kev && (
        <span className="rounded-sm bg-[var(--color-severity-critical-subtle)] px-1.5 py-0.5 text-2xs font-semibold uppercase text-[var(--color-severity-critical)]">
          KEV
        </span>
      )}
      {showEpss && (
        <span className="rounded-sm bg-[var(--color-verdict-uncertain-subtle)] px-1.5 py-0.5 text-2xs font-semibold uppercase text-[var(--color-verdict-uncertain)]">
          EPSS {Math.round((epssPercentile ?? 0) * 100)}%
        </span>
      )}
      {showNew && (
        <span className="rounded-sm bg-[var(--color-accent-subtle)] px-1.5 py-0.5 text-2xs font-semibold uppercase text-[var(--color-accent)]">
          NEW
        </span>
      )}
    </span>
  )
}
