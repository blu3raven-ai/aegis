"use client"

import type { NotificationDelivery } from "@/lib/client/destinations-api"

const STATUS_STYLES: Record<string, { dot: string; label: string }> = {
  delivered: { dot: "bg-[var(--color-status-ok)]", label: "text-[var(--color-status-ok)]" },
  failed: { dot: "bg-[var(--color-severity-critical)]", label: "text-[var(--color-severity-critical)]" },
  pending: { dot: "bg-[var(--color-text-tertiary)]", label: "text-[var(--color-text-tertiary)]" },
  retry: { dot: "bg-[var(--color-severity-medium)]", label: "text-[var(--color-severity-medium)]" },
}

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const secs = Math.floor(diff / 1000)
  if (secs < 60) return `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

interface DeliveriesHistoryListProps {
  deliveries: NotificationDelivery[]
  loading?: boolean
  error?: string
}

export function DeliveriesHistoryList({ deliveries, loading, error }: DeliveriesHistoryListProps) {
  if (loading) {
    return (
      <div className="space-y-2">
        {[0, 1, 2].map((i) => (
          <div
            key={i}
            className="h-10 animate-pulse rounded-lg bg-[var(--color-surface-raised)]"
          />
        ))}
      </div>
    )
  }

  if (error) {
    return (
      <p className="text-sm text-[var(--color-severity-critical)]">{error}</p>
    )
  }

  if (deliveries.length === 0) {
    return (
      <p className="text-sm text-[var(--color-text-tertiary)]">
        No delivery attempts recorded yet.
      </p>
    )
  }

  return (
    <div className="divide-y divide-[var(--color-border-divider)]">
      {deliveries.map((d) => {
        const s = STATUS_STYLES[d.status] ?? STATUS_STYLES.pending
        return (
          <div key={d.id} className="flex items-start gap-3 py-2.5">
            <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${s.dot}`} aria-hidden="true" />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className={`text-xs font-semibold capitalize ${s.label}`}>{d.status}</span>
                <span className="text-[11px] text-[var(--color-text-tertiary)]">
                  {d.event_type}
                </span>
              </div>
              {d.payload_summary && (
                <p className="truncate text-[11px] text-[var(--color-text-secondary)]">
                  {d.payload_summary}
                </p>
              )}
              {d.error && (
                <p className="mt-0.5 truncate text-[11px] text-[var(--color-severity-critical)]">
                  {d.error}
                </p>
              )}
            </div>
            <div className="shrink-0 text-right">
              {d.response_code != null && (
                <span className="text-[11px] text-[var(--color-text-tertiary)]">
                  HTTP {d.response_code}
                </span>
              )}
              <p className="text-[11px] text-[var(--color-text-tertiary)]">
                {relativeTime(d.attempted_at)}
              </p>
            </div>
          </div>
        )
      })}
    </div>
  )
}
