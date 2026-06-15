"use client"

import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"
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
  return (
    <div className="overflow-x-auto border-t border-[var(--color-border)]">
      <Table className="table-fixed">
        <colgroup>
          <col className="w-[25%]" />
          <col className="w-[15%]" />
          <col className="w-[20%]" />
          <col className="w-[20%]" />
          <col className="w-[15%]" />
          <col className="w-8" />
        </colgroup>
        <Thead>
          <Tr>
            <Th className="py-2.5 whitespace-nowrap">Runner</Th>
            <Th className="py-2.5 whitespace-nowrap">Status</Th>
            <Th className="py-2.5 whitespace-nowrap hidden sm:table-cell">Platform</Th>
            <Th className="py-2.5 whitespace-nowrap hidden md:table-cell">Health</Th>
            <Th className="py-2.5 whitespace-nowrap hidden md:table-cell">Concurrency</Th>
            <Th className="py-2.5 w-8" />
          </Tr>
        </Thead>
        <Tbody divided={false}>
          {runners.map((r) => (
            <Tr
              key={r.id}
              onClick={() => onRowClick(r)}
              interactive
              className="cursor-pointer border-t border-[var(--color-border)]"
            >
              <Td className="font-medium text-[var(--color-text-primary)]">{r.name}</Td>
              <Td>
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
              </Td>
              <Td className="hidden text-[var(--color-text-secondary)] sm:table-cell">
                {r.os ? `${r.os.charAt(0).toUpperCase() + r.os.slice(1)}/${r.arch}` : "—"}
              </Td>
              <Td className="hidden md:table-cell">
                <MiniHealthBar percent={r.healthPercent} />
              </Td>
              <Td className="hidden tabular-nums text-[var(--color-text-secondary)] md:table-cell">
                {r.maxConcurrent ?? "—"}
              </Td>
              <Td className="text-[var(--color-text-secondary)]">
                <svg
                  className="h-4 w-4"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth={2}
                >
                  <path d="M9 18l6-6-6-6" />
                </svg>
              </Td>
            </Tr>
          ))}
        </Tbody>
      </Table>
    </div>
  )
}
