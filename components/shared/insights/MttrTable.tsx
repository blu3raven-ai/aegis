"use client"

import type { MttrRow } from "@/lib/client/temporal-api"

function Skeleton() {
  return (
    <div className="flex flex-col gap-2 p-4 animate-pulse">
      <div className="h-3 w-full rounded bg-[var(--color-surface-raised)]" />
      {[...Array(4)].map((_, i) => (
        <div key={i} className="h-3 w-4/5 rounded bg-[var(--color-surface-raised)]" />
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

function formatDuration(ms: number): string {
  if (ms <= 0) return "—"
  const seconds = ms / 1000
  if (seconds < 60) return `${Math.round(seconds)}s`
  const minutes = seconds / 60
  if (minutes < 60) return `${Math.round(minutes)}m`
  const hours = minutes / 60
  if (hours < 24) return `${Math.round(hours)}h`
  const days = hours / 24
  return `${Math.round(days)}d`
}

interface MttrTableProps {
  rows: MttrRow[]
  loading: boolean
  error: boolean
}

export function MttrTable({ rows, loading, error }: MttrTableProps) {
  if (loading) return <Skeleton />
  if (error) return <ErrorState />
  if (rows.length === 0) return <EmptyState />

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[12px]" aria-label="MTTR by scanner">
        <thead>
          <tr className="border-b border-[var(--color-border)]">
            <th className="pb-2 pr-4 font-semibold text-[var(--color-text-secondary)]">Scanner</th>
            <th className="pb-2 pr-4 text-right font-semibold text-[var(--color-text-secondary)]">Avg MTTR</th>
            <th className="pb-2 text-right font-semibold text-[var(--color-text-secondary)]">Samples</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.group} className="border-b border-[var(--color-border-divider)] last:border-0">
              <td className="py-2 pr-4 font-medium text-[var(--color-text-primary)]">
                {row.group}
              </td>
              <td className="py-2 pr-4 text-right font-mono text-[var(--color-text-secondary)]">
                {formatDuration(row.avg_ms)}
              </td>
              <td className="py-2 text-right font-mono text-[var(--color-text-tertiary)]">
                {row.sample_count.toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
