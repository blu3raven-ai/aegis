"use client"

import Link from "next/link"
import { type ControlSummaryItem, deriveControlStatus } from "@/lib/client/compliance-api"
import { ControlBadge } from "./ControlBadge"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-[var(--color-severity-critical)]",
  high: "text-[var(--color-severity-high)]",
  medium: "text-[var(--color-severity-medium)]",
  low: "text-[var(--color-severity-low)]",
}

function StatusPill({ ctrl }: { ctrl: ControlSummaryItem }) {
  const status = deriveControlStatus(ctrl)
  if (status === "met") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-[var(--color-status-ok-subtle)] px-2 py-0.5 text-[11px] font-medium text-[var(--color-status-ok)]">
        <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-status-ok)]" />
        compliant
      </span>
    )
  }
  if (status === "partial") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-[var(--color-severity-medium-subtle)] px-2 py-0.5 text-[11px] font-medium text-[var(--color-severity-medium)]">
        <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-severity-medium)]" />
        partial
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-[var(--color-severity-critical-subtle)] px-2 py-0.5 text-[11px] font-medium text-[var(--color-severity-critical)]">
      <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-severity-critical)]" />
      at risk
    </span>
  )
}

interface ControlsSummaryTableProps {
  controls: ControlSummaryItem[]
  framework: string
  statusFilter?: "all" | "unmet" | "partial" | "met"
}

export function ControlsSummaryTable({ controls, framework, statusFilter = "all" }: ControlsSummaryTableProps) {
  if (controls.length === 0) {
    return (
      <div className="flex items-center justify-center py-12 text-sm text-[var(--color-text-secondary)]">
        No controls found for this framework.
      </div>
    )
  }

  const filtered =
    statusFilter === "all"
      ? controls
      : controls.filter((c) => deriveControlStatus(c) === statusFilter)

  if (filtered.length === 0) {
    return (
      <div className="flex items-center justify-center py-12 text-sm text-[var(--color-text-secondary)]">
        No controls match the {statusFilter} filter.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <Table>
        <Thead className="bg-transparent">
          <Tr>
            <Th className="px-0 pr-4 pt-0 pb-2">Control</Th>
            <Th className="px-0 pr-4 pt-0 pb-2">Title</Th>
            <Th className="px-0 pr-4 pt-0 pb-2 text-right">Findings</Th>
            <Th className="px-0 pr-4 pt-0 pb-2">Highest Severity</Th>
            <Th className="px-0 pr-4 pt-0 pb-2">Status</Th>
            <Th className="px-0 pt-0 pb-2 text-right" />
          </Tr>
        </Thead>
        <Tbody>
          {filtered.map((ctrl) => {
            const href = `/compliance/${framework}/${encodeURIComponent(ctrl.control_id)}`
            return (
              <Tr
                key={ctrl.control_id}
                interactive
                className="group"
              >
                <Td className="px-0 py-3 pr-4">
                  <Link href={href} className="hover:underline">
                    <ControlBadge framework={framework} controlId={ctrl.control_id} />
                  </Link>
                  {ctrl.category && (
                    <div className="mt-1 text-2xs uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
                      {ctrl.category}
                    </div>
                  )}
                </Td>
                <Td className="px-0 py-3 pr-4">
                  <Link
                    href={href}
                    className="font-medium text-[var(--color-text-primary)] hover:underline"
                  >
                    {ctrl.title}
                  </Link>
                </Td>
                <Td className="px-0 py-3 pr-4 text-right font-mono text-[var(--color-text-primary)]">
                  {ctrl.finding_count > 0 ? (
                    <Link
                      href={href}
                      className="font-semibold text-[var(--color-severity-critical)] hover:underline"
                    >
                      {ctrl.finding_count}
                    </Link>
                  ) : (
                    <span className="text-[var(--color-text-secondary)]">0</span>
                  )}
                </Td>
                <Td className="px-0 py-3 pr-4">
                  {ctrl.highest_severity ? (
                    <span
                      className={`font-medium capitalize ${SEVERITY_COLORS[ctrl.highest_severity] ?? "text-[var(--color-text-secondary)]"}`}
                    >
                      {ctrl.highest_severity}
                    </span>
                  ) : (
                    <span className="text-[var(--color-text-secondary)]">—</span>
                  )}
                </Td>
                <Td className="px-0 py-3 pr-4">
                  <StatusPill ctrl={ctrl} />
                </Td>
                <Td className="px-0 py-3 text-right">
                  <Link
                    href={href}
                    className="text-[var(--color-text-tertiary)] hover:text-[var(--color-text-secondary)]"
                    tabIndex={-1}
                    aria-hidden="true"
                  >
                    ›
                  </Link>
                </Td>
              </Tr>
            )
          })}
        </Tbody>
      </Table>
    </div>
  )
}
