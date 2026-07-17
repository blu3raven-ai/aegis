"use client"

import { useState } from "react"
import Link from "next/link"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"
import { Button } from "@/components/ui/Button"
import { approveRunner } from "@/lib/client/settings/use-runners"
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
      <div className="h-1.5 w-12 overflow-hidden rounded-full bg-[var(--color-border-strong)]">
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
  canApprove: boolean
  onRowClick: (runner: Runner) => void
  onChange: () => void
}

/**
 * Flush runner list, designed to sit inside the RemotePanel card — uses a
 * top border to separate from the status header but has no outer rounded
 * border of its own.
 */
export function RemoteRunnerList({ runners, canApprove, onRowClick, onChange }: RemoteRunnerListProps) {
  return (
    <div className="overflow-x-auto border-t border-[var(--color-border)]">
      <Table className="table-fixed">
        <colgroup>
          <col className="w-[25%]" />
          <col className="w-[15%]" />
          <col className="w-[20%]" />
          <col className="w-[15%]" />
          <col className="w-[15%]" />
          <col className="w-[10%]" />
        </colgroup>
        <Thead>
          <Tr>
            <Th className="py-2.5 whitespace-nowrap">Runner</Th>
            <Th className="py-2.5 whitespace-nowrap">Status</Th>
            <Th className="py-2.5 whitespace-nowrap hidden sm:table-cell">Platform</Th>
            <Th className="py-2.5 whitespace-nowrap hidden md:table-cell">Health</Th>
            <Th className="py-2.5 whitespace-nowrap hidden md:table-cell">Concurrency</Th>
            <Th className="py-2.5" />
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
              <Td className="font-medium text-[var(--color-text-primary)]">
                {/* Keep <Link> so right-click / cmd+click / keyboard still works */}
                <Link
                  href={`/settings/runners/${r.id}`}
                  className="hover:underline"
                  onClick={(e) => e.stopPropagation()}
                >
                  {r.name}
                </Link>
              </Td>
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
              <Td>
                <RowActions runner={r} canApprove={canApprove} onChange={onChange} />
              </Td>
            </Tr>
          ))}
        </Tbody>
      </Table>
    </div>
  )
}


/**
 * Per-row actions. Pending runners get a quick inline Approve so admins
 * don't have to drill into the detail page just to flip the gate. Other
 * statuses fall back to the chevron — the detail page has the full
 * lifecycle controls (Revoke / Rotate / Delete).
 */
function RowActions({
  runner,
  canApprove,
  onChange,
}: {
  runner: Runner
  canApprove: boolean
  onChange: () => void
}) {
  const [busy, setBusy] = useState(false)

  if (runner.status === "pending_approval" && canApprove) {
    return (
      <Button
        variant="primary"
        size="xs"
        isLoading={busy}
        disabled={busy}
        onClick={async (e) => {
          e.stopPropagation()
          setBusy(true)
          try {
            await approveRunner(runner.id)
            onChange()
          } finally {
            setBusy(false)
          }
        }}
      >
        Approve
      </Button>
    )
  }

  return (
    <span className="flex justify-end text-[var(--color-text-secondary)]">
      <svg
        className="h-4 w-4"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={2}
      >
        <path d="M9 18l6-6-6-6" />
      </svg>
    </span>
  )
}
