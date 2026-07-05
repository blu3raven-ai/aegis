"use client"

import type { TopAuthor } from "@/lib/client/temporal-api"

const SEV_COLORS: Record<string, string> = {
  critical: "var(--color-severity-critical)",
  high:     "var(--color-severity-high)",
  medium:   "var(--color-severity-medium)",
  low:      "var(--color-severity-low)",
}

const SEV_ORDER = ["critical", "high", "medium", "low"] as const

function Skeleton() {
  return (
    <div className="flex flex-col gap-2 p-4 animate-pulse">
      {[...Array(5)].map((_, i) => (
        <div key={i} className="flex items-center gap-2">
          <div className="h-2.5 w-24 rounded bg-[var(--color-surface-raised)]" />
          <div className="h-2.5 flex-1 rounded bg-[var(--color-surface-raised)]" />
        </div>
      ))}
    </div>
  )
}

function EmptyState() {
  return (
    <div className="flex min-h-[160px] items-center justify-center text-center px-6">
      <p className="text-[13px] text-[var(--color-text-secondary)]">
        No findings in this window. Try widening the time range.
      </p>
    </div>
  )
}

function ErrorState() {
  return (
    <div className="flex min-h-[160px] items-center justify-center text-center px-6">
      <p className="text-[13px] text-[var(--color-text-secondary)]">
        Couldn't load — temporal correlation may be disabled (
        <code className="font-mono text-[12px] text-[var(--color-text-primary)]">AEGIS_CORRELATION_ENABLED=true</code>
        {" "}required).
      </p>
    </div>
  )
}

interface TopAuthorsListProps {
  authors: TopAuthor[]
  loading: boolean
  error: boolean
}

export function TopAuthorsList({ authors, loading, error }: TopAuthorsListProps) {
  if (loading) return <Skeleton />
  if (error) return <ErrorState />
  if (authors.length === 0) return <EmptyState />

  const maxTotal = Math.max(1, ...authors.map((a) => a.total))

  return (
    <ul className="flex flex-col gap-2 py-1" role="list" aria-label="Top authors by findings introduced">
      {authors.map((author) => {
        const pct = (author.total / maxTotal) * 100
        return (
          <li key={author.author} className="flex flex-col gap-0.5">
            <div className="flex items-baseline justify-between gap-2">
              <span className="max-w-[160px] truncate text-[12px] font-medium text-[var(--color-text-primary)]">
                {author.author}
              </span>
              <span className="shrink-0 font-mono text-[11px] text-[var(--color-text-secondary)]">
                {author.total}
              </span>
            </div>
            {/* Severity-segmented bar */}
            <div
              className="relative h-2 overflow-hidden rounded-full bg-[var(--color-surface-raised)]"
              role="img"
              aria-label={`${author.author}: ${author.total} findings`}
            >
              <div
                className="absolute inset-y-0 left-0 flex overflow-hidden rounded-full"
                style={{ width: `${pct}%` }}
              >
                {SEV_ORDER.map((sev) => {
                  const count = author.by_severity[sev] ?? 0
                  if (count === 0) return null
                  const segPct = (count / author.total) * 100
                  return (
                    <span
                      key={sev}
                      style={{ width: `${segPct}%`, background: SEV_COLORS[sev] }}
                      title={`${sev}: ${count}`}
                    />
                  )
                })}
              </div>
            </div>
          </li>
        )
      })}
    </ul>
  )
}
