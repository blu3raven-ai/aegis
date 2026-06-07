"use client"

import type { SourceConnection } from "@/lib/shared/sources-types"
import { timeAgo } from "@/lib/shared/time-ago"

// ─── Props ────────────────────────────────────────────────────────────────────

interface SourceKpiStripProps {
  connections: SourceConnection[]
}

// ─── Component ────────────────────────────────────────────────────────────────

export function SourceKpiStrip({ connections }: SourceKpiStripProps) {
  const total = connections.length

  const healthy = connections.filter((c) => c.status === "connected" || c.status === "syncing").length
  const syncing = connections.filter((c) => c.status === "syncing").length

  const issues = connections.filter(
    (c) => c.status === "error" || c.status === "disconnected",
  ).length

  const lastSyncedTimestamps = connections
    .map((c) => c.lastSyncedAt)
    .filter((ts): ts is string => Boolean(ts))
    .map((ts) => new Date(ts).getTime())

  const latestSyncMs =
    lastSyncedTimestamps.length > 0 ? Math.max(...lastSyncedTimestamps) : null
  const latestSyncIso = latestSyncMs ? new Date(latestSyncMs).toISOString() : null

  const lastSyncValue = latestSyncIso ? timeAgo(latestSyncIso) : "—"
  const lastSyncNote = latestSyncIso
    ? new Date(latestSyncIso).toLocaleString()
    : "No syncs recorded"

  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-2 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-3">
      <div className="flex items-center gap-2 text-sm">
        <span className="font-semibold tabular-nums text-[var(--color-text-primary)]">{total}</span>
        <span className="text-[var(--color-text-secondary)]">connection{total === 1 ? "" : "s"}</span>
      </div>

      <span className="hidden sm:block h-4 w-px bg-[var(--color-border-strong)]" />

      <div className="flex items-center gap-1.5 text-sm">
        <span className={`h-2 w-2 rounded-full ${healthy === total && total > 0 ? "bg-[var(--color-status-ok)]" : issues > 0 ? "bg-[var(--color-severity-critical)]" : "bg-[var(--color-text-tertiary)]"}`} aria-hidden="true" />
        {issues > 0 ? (
          <span className="text-[var(--color-severity-critical)] font-medium">{issues} need{issues === 1 ? "s" : ""} attention</span>
        ) : syncing > 0 ? (
          <span className="text-[var(--color-severity-medium)] font-medium">{syncing} syncing</span>
        ) : total > 0 ? (
          <span className="text-[var(--color-status-ok)] font-medium">All healthy</span>
        ) : (
          <span className="text-[var(--color-text-secondary)]">No connections</span>
        )}
      </div>

      {latestSyncIso && (
        <>
          <span className="hidden sm:block h-4 w-px bg-[var(--color-border-strong)]" />
          <div className="flex items-center gap-1.5 text-sm text-[var(--color-text-secondary)]">
            <span>Last sync</span>
            <span className="font-medium tabular-nums text-[var(--color-text-primary)]" title={lastSyncNote}>
              {lastSyncValue}
            </span>
          </div>
        </>
      )}
    </div>
  )
}
