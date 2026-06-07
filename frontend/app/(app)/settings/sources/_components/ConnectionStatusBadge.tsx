"use client"

import type { ConnectionStatus } from "@/lib/shared/sources-types"

const STATUS_CONFIG: Record<ConnectionStatus, { label: string; color: string; animate?: boolean }> = {
  connected: { label: "Connected", color: "var(--color-status-ok)" },
  syncing: { label: "Syncing", color: "var(--color-accent)", animate: true },
  error: { label: "Error", color: "var(--color-severity-critical)" },
  disconnected: { label: "Disconnected", color: "var(--color-severity-critical)" },
  "not-synced": { label: "Not synced", color: "var(--color-text-secondary)" },
}

export function ConnectionStatusBadge({ status }: { status: ConnectionStatus }) {
  const config = STATUS_CONFIG[status] ?? STATUS_CONFIG["not-synced"]
  return (
    <span className="flex items-center gap-1.5 text-xs font-medium">
      <span
        className={`inline-block h-2 w-2 rounded-full ${config.animate ? "animate-pulse" : ""}`}
        style={{ backgroundColor: config.color }}
      />
      <span style={{ color: config.color }}>{config.label}</span>
    </span>
  )
}
