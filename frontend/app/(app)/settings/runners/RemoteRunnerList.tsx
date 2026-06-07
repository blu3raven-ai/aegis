"use client"

import type { Runner } from "./types"

const STATUS_DOT: Record<string, string> = {
  online: "bg-[var(--color-status-ok)]",
  stale: "bg-[var(--color-state-pending)]",
  offline: "bg-[var(--color-text-tertiary)]",
  pending_approval: "bg-[var(--color-accent)]",
}

const STATUS_LABEL: Record<string, string> = {
  online: "Online",
  stale: "Stale",
  offline: "Offline",
  pending_approval: "Pending",
}

function MiniHealthBar({ percent }: { percent: number | null | undefined }) {
  if (percent == null) return <span className="text-[var(--color-text-secondary)]">—</span>
  const clamped = Math.max(0, Math.min(100, percent))
  const color =
    clamped >= 90
      ? "bg-[var(--color-status-ok)]"
      : clamped >= 50
        ? "bg-[var(--color-state-pending)]"
        : "bg-[var(--color-severity-critical)]"
  return (
    <div className="flex items-center gap-1.5">
      <div className="h-1.5 w-12 overflow-hidden rounded-full bg-[var(--color-surface-raised)]">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${clamped}%` }} />
      </div>
      <span className="text-xs tabular-nums text-[var(--color-text-secondary)]">
        {Math.round(clamped)}%
      </span>
    </div>
  )
}

interface RemoteRunnerListProps {
  runners: Runner[]
  onRowClick: (runner: Runner) => void
}

/**
 * Flush runner list, designed to sit inside the RemotePanel card — uses a
 * top border to separate from the status header but has no outer rounded
 * border of its own.
 */
export function RemoteRunnerList({ runners, onRowClick }: RemoteRunnerListProps) {
  const thCls =
    "px-4 py-2.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--color-text-tertiary)] whitespace-nowrap"

  return (
    <div className="overflow-x-auto border-t border-[var(--color-border)]">
      <table className="w-full table-fixed text-left text-sm">
        <colgroup>
          <col className="w-[25%]" />
          <col className="w-[15%]" />
          <col className="w-[20%]" />
          <col className="w-[20%]" />
          <col className="w-[15%]" />
          <col className="w-8" />
        </colgroup>
        <thead className="bg-[var(--color-surface-2)]">
          <tr>
            <th className={thCls}>Runner</th>
            <th className={thCls}>Status</th>
            <th className={`${thCls} hidden sm:table-cell`}>Platform</th>
            <th className={`${thCls} hidden md:table-cell`}>Health</th>
            <th className={`${thCls} hidden md:table-cell`}>Concurrency</th>
            <th className={`${thCls} w-8`} />
          </tr>
        </thead>
        <tbody>
          {runners.map((r) => (
            <tr
              key={r.id}
              onClick={() => onRowClick(r)}
              className="cursor-pointer border-t border-[var(--color-border)] transition-colors hover:bg-[var(--color-surface-raised)]"
            >
              <td className="px-4 py-3 font-medium text-[var(--color-text-primary)]">{r.name}</td>
              <td className="px-4 py-3">
                <span className="flex items-center gap-2">
                  <span
                    className={`h-2 w-2 rounded-full ${
                      STATUS_DOT[r.status] ?? "bg-[var(--color-text-tertiary)]"
                    }`}
                  />
                  <span className="text-[var(--color-text-secondary)]">
                    {STATUS_LABEL[r.status] ?? r.status}
                  </span>
                </span>
              </td>
              <td className="hidden px-4 py-3 text-[var(--color-text-secondary)] sm:table-cell">
                {r.os ? `${r.os.charAt(0).toUpperCase() + r.os.slice(1)}/${r.arch}` : "—"}
              </td>
              <td className="hidden px-4 py-3 md:table-cell">
                <MiniHealthBar percent={r.healthPercent} />
              </td>
              <td className="hidden px-4 py-3 tabular-nums text-[var(--color-text-secondary)] md:table-cell">
                {r.maxConcurrent ?? "—"}
              </td>
              <td className="px-4 py-3 text-[var(--color-text-secondary)]">
                <svg
                  className="h-4 w-4"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth={2}
                >
                  <path d="M9 18l6-6-6-6" />
                </svg>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
