"use client"

import type { Runner } from "./types"

const STATUS_DOT: Record<string, string> = {
  online: "bg-emerald-500",
  stale: "bg-amber-400",
  offline: "bg-gray-400",
  pending_approval: "bg-blue-400",
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
  const color = clamped >= 90 ? "bg-emerald-500" : clamped >= 50 ? "bg-amber-400" : "bg-red-500"
  return (
    <div className="flex items-center gap-1.5">
      <div className="h-1.5 w-12 rounded-full bg-[var(--color-surface-raised)] overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${clamped}%` }} />
      </div>
      <span className="text-xs tabular-nums text-[var(--color-text-secondary)]">{Math.round(clamped)}%</span>
    </div>
  )
}

interface RunnerTableProps {
  runners: Runner[]
  label: string
  showAddButton: boolean
  isLocalMode?: boolean
  onAddClick?: () => void
  onRowClick: (runner: Runner) => void
}

export function RunnerTable({ runners, label, showAddButton, isLocalMode, onAddClick, onRowClick }: RunnerTableProps) {
  const thCls = "px-4 py-3 text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)] whitespace-nowrap"

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-[var(--color-text-primary)]">{label}</p>
        {showAddButton && onAddClick && (
          <button
            type="button"
            onClick={onAddClick}
            className="rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-white hover:bg-[var(--color-accent-hover)]"
          >
            Add runner
          </button>
        )}
      </div>

      {runners.length === 0 ? (
        <div className="rounded-xl border border-dashed border-[var(--color-border)] px-6 py-12 text-center">
          <p className="text-sm font-medium text-[var(--color-text-primary)]">
            {isLocalMode ? "Local runner not connected" : "No runners registered"}
          </p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            {isLocalMode
              ? "The local runner registers automatically when the runner service starts. Run docker compose up to connect it."
              : "Click \"Add runner\" to register your first runner."}
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-[var(--color-border)]">
          <table className="w-full table-fixed text-left text-sm">
            <colgroup>
              <col className="w-[25%]" />
              <col className="w-[15%]" />
              <col className="w-[20%]" />
              <col className="w-[20%]" />
              <col className="w-[15%]" />
              <col className="w-8" />
            </colgroup>
            <thead className="border-b border-[var(--color-border)] bg-[var(--color-surface-raised)]">
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
                  className="border-b border-[var(--color-border)] last:border-0 cursor-pointer hover:bg-[var(--color-surface-raised)] transition-colors"
                >
                  <td className="px-4 py-3 font-medium text-[var(--color-text-primary)]">{r.name}</td>
                  <td className="px-4 py-3">
                    <span className="flex items-center gap-2">
                      <span className={`h-2 w-2 rounded-full ${STATUS_DOT[r.status] ?? "bg-gray-400"}`} />
                      <span className="text-[var(--color-text-secondary)]">{STATUS_LABEL[r.status] ?? r.status}</span>
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
                    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                      <path d="M9 18l6-6-6-6" />
                    </svg>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
