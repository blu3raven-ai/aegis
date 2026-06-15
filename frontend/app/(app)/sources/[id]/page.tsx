"use client"

import { use, useEffect, useState } from "react"
import { KpiCard } from "@/components/ui/KpiCard"
import { getSourceConnection } from "@/lib/client/sources-api"
import type { SourceConnection } from "@/lib/shared/sources-types"
import { timeAgo } from "@/lib/shared/time-ago"

// ─── Status mapping ────────────────────────────────────────────────────────────

function statusToKpiStatus(
  status: SourceConnection["status"],
): "neutral" | "success" | "warning" | "danger" {
  switch (status) {
    case "connected": return "success"
    case "syncing":   return "warning"
    case "error":     return "danger"
    case "disconnected": return "danger"
    case "not-synced":   return "neutral"
  }
}

const STATUS_LABEL: Record<SourceConnection["status"], string> = {
  "connected":    "Connected",
  "syncing":      "Syncing",
  "error":        "Error",
  "disconnected": "Disconnected",
  "not-synced":   "Not synced",
}

// ─── Page ──────────────────────────────────────────────────────────────────────

export default function SourceOverviewPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = use(params)
  const [connection, setConnection] = useState<SourceConnection | null>(null)

  useEffect(() => {
    let cancelled = false
    getSourceConnection(id).then((r) => {
      if (!cancelled && r.ok) setConnection(r.data.connection)
    })
    return () => { cancelled = true }
  }, [id])

  return (
    <div className="px-6 py-6 space-y-6">
      {/* KPI strip */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiCard
          label="Discovered items"
          value={connection?.discoveredItemCount != null ? connection.discoveredItemCount.toLocaleString() : "—"}
        />
        <KpiCard
          label="Last sync"
          value={connection?.lastSyncedAt ? timeAgo(connection.lastSyncedAt) : "—"}
        />
        <KpiCard
          label="Connection status"
          value={connection ? STATUS_LABEL[connection.status] : "—"}
          status={connection ? statusToKpiStatus(connection.status) : "neutral"}
        />
        <KpiCard
          label="Next sync"
          value={connection?.nextSyncAt ? timeAgo(connection.nextSyncAt) : "—"}
        />
      </div>

      {/* Recent activity */}
      <section>
        <h2 className="text-base font-semibold text-[var(--color-text-primary)] mb-3">
          Recent activity
        </h2>
        <p className="text-sm text-[var(--color-text-secondary)]">
          Activity feed coming with v0.2.5 SCM integrations.
        </p>
      </section>
    </div>
  )
}
