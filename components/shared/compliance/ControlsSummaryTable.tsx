"use client"

import Link from "next/link"
import type { ControlSummaryItem } from "@/lib/client/compliance-api"
import { ControlBadge } from "./ControlBadge"

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-[var(--color-severity-critical)]",
  high: "text-[var(--color-severity-high)]",
  medium: "text-[var(--color-severity-medium)]",
  low: "text-[var(--color-severity-low)]",
}

function StatusPill({ findingCount }: { findingCount: number }) {
  if (findingCount === 0) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-[var(--color-status-ok-subtle)] px-2 py-0.5 text-[11px] font-medium text-[var(--color-status-ok)]">
        <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-status-ok)]" />
        compliant
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
}

export function ControlsSummaryTable({ controls, framework }: ControlsSummaryTableProps) {
  if (controls.length === 0) {
    return (
      <div className="flex items-center justify-center py-12 text-[13px] text-[var(--color-text-secondary)]">
        No controls found for this framework.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-[13px]">
        <thead>
          <tr className="border-b border-[var(--color-border)]">
            <th className="pb-2 pr-4 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
              Control
            </th>
            <th className="pb-2 pr-4 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
              Title
            </th>
            <th className="pb-2 pr-4 text-right text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
              Findings
            </th>
            <th className="pb-2 pr-4 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
              Highest Severity
            </th>
            <th className="pb-2 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
              Status
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--color-border)]">
          {controls.map((ctrl) => (
            <tr
              key={ctrl.control_id}
              className="group transition-colors hover:bg-[var(--color-surface-raised)]"
            >
              <td className="py-3 pr-4">
                <Link
                  href={`/compliance/${framework}/${encodeURIComponent(ctrl.control_id)}`}
                  className="hover:underline"
                >
                  <ControlBadge framework={framework} controlId={ctrl.control_id} />
                </Link>
              </td>
              <td className="py-3 pr-4">
                <Link
                  href={`/compliance/${framework}/${encodeURIComponent(ctrl.control_id)}`}
                  className="font-medium text-[var(--color-text-primary)] hover:underline"
                >
                  {ctrl.title}
                </Link>
                {ctrl.category && (
                  <div className="mt-0.5 text-[11px] text-[var(--color-text-secondary)]">
                    {ctrl.category}
                  </div>
                )}
              </td>
              <td className="py-3 pr-4 text-right font-mono text-[var(--color-text-primary)]">
                {ctrl.finding_count > 0 ? (
                  <Link
                    href={`/compliance/${framework}/${encodeURIComponent(ctrl.control_id)}`}
                    className="font-semibold text-[var(--color-severity-critical)] hover:underline"
                  >
                    {ctrl.finding_count}
                  </Link>
                ) : (
                  <span className="text-[var(--color-text-secondary)]">0</span>
                )}
              </td>
              <td className="py-3 pr-4">
                {ctrl.highest_severity ? (
                  <span
                    className={`font-medium capitalize ${SEVERITY_COLORS[ctrl.highest_severity] ?? "text-[var(--color-text-secondary)]"}`}
                  >
                    {ctrl.highest_severity}
                  </span>
                ) : (
                  <span className="text-[var(--color-text-secondary)]">—</span>
                )}
              </td>
              <td className="py-3">
                <StatusPill findingCount={ctrl.finding_count} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
