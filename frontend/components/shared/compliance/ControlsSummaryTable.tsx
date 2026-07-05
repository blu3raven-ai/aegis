"use client"

import Link from "next/link"
import { useRouter } from "next/navigation"
import { type ControlSummaryItem, deriveControlStatus } from "@/lib/client/compliance-api"
import { ControlBadge } from "./ControlBadge"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-[var(--color-severity-critical-text)]",
  high: "text-[var(--color-severity-high-text)]",
  medium: "text-[var(--color-severity-medium-text)]",
  low: "text-[var(--color-severity-low-text)]",
}

// Map internal status keys to the user-facing vocabulary used by the pills and
// filter chips, so the empty-filter message reads consistently.
const STATUS_FILTER_LABELS: Record<"unmet" | "partial" | "met", string> = {
  unmet: "At Risk",
  partial: "Partial",
  met: "Compliant",
}

function StatusPill({ ctrl }: { ctrl: ControlSummaryItem }) {
  const status = deriveControlStatus(ctrl)
  if (status === "met") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-[var(--color-status-ok-subtle)] px-2 py-0.5 text-2xs font-medium text-[var(--color-status-ok-text)]">
        <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-status-ok)]" />
        Compliant
      </span>
    )
  }
  if (status === "partial") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-[var(--color-severity-medium-subtle)] px-2 py-0.5 text-2xs font-medium text-[var(--color-severity-medium-text)]">
        <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-severity-medium)]" />
        Partial
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-[var(--color-severity-critical-subtle)] px-2 py-0.5 text-2xs font-medium text-[var(--color-severity-critical-text)]">
      <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-severity-critical)]" />
      At Risk
    </span>
  )
}

interface ControlsSummaryTableProps {
  controls: ControlSummaryItem[]
  framework: string
  statusFilter?: "all" | "unmet" | "partial" | "met"
}

export function ControlsSummaryTable({ controls, framework, statusFilter = "all" }: ControlsSummaryTableProps) {
  const router = useRouter()

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
        No controls match the {STATUS_FILTER_LABELS[statusFilter as "unmet" | "partial" | "met"] ?? statusFilter} filter.
      </div>
    )
  }

  // Group by control family (category) so a 30+ control framework reads as the
  // auditor's mental model — Logical Access, Risk Assessment, … — rather than a
  // flat scroll. Insertion order follows the control_id sort from the backend,
  // which keeps each family contiguous.
  const groups: { category: string; items: ControlSummaryItem[] }[] = []
  const indexByCategory = new Map<string, number>()
  for (const c of filtered) {
    const category = c.category || "Uncategorized"
    let idx = indexByCategory.get(category)
    if (idx === undefined) {
      idx = groups.length
      indexByCategory.set(category, idx)
      groups.push({ category, items: [] })
    }
    groups[idx].items.push(c)
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
            <Th className="px-0 pr-4 pt-0 pb-2">Owner / Due</Th>
            <Th className="px-0 pt-0 pb-2 text-right" />
          </Tr>
        </Thead>
        <Tbody>
          {groups.map((group) => {
            const met = group.items.filter((c) => deriveControlStatus(c) === "met").length
            return [
              <Tr key={`group-${group.category}`} className="bg-transparent">
                <Td colSpan={7} className="px-0 pt-5 pb-1.5 first:pt-1">
                  <div className="flex items-baseline gap-2">
                    <span className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
                      {group.category}
                    </span>
                    <span className="text-2xs tabular-nums text-[var(--color-text-tertiary)]">
                      {met}/{group.items.length} passing
                    </span>
                  </div>
                </Td>
              </Tr>,
              ...group.items.map((ctrl) => {
                const href = `/compliance/${framework}/${encodeURIComponent(ctrl.control_id)}`
                return (
                  // Whole-row click is a mouse enhancement; the control title is a
                  // real <Link> so the row stays keyboard-focusable and supports
                  // open-in-new-tab / copy-link. The <tr> keeps its implicit
                  // role="row" (no role override), and the click handler ignores
                  // events that land on the inner link to avoid double-navigation.
                  <Tr
                    key={ctrl.control_id}
                    interactive
                    onClick={(e) => {
                      if ((e.target as HTMLElement).closest("a,button")) return
                      router.push(href)
                    }}
                    className="group cursor-pointer"
                  >
                    <Td className="px-0 py-3 pr-4">
                      <ControlBadge framework={framework} controlId={ctrl.control_id} />
                    </Td>
                    <Td className="px-0 py-3 pr-4">
                      <Link
                        href={href}
                        className="rounded-sm font-medium text-[var(--color-text-primary)] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-background)]"
                      >
                        {ctrl.title}
                      </Link>
                    </Td>
                    <Td className="px-0 py-3 pr-4 text-right font-mono">
                      {ctrl.finding_count > 0 ? (
                        <span className="font-semibold text-[var(--color-severity-critical-text)]">
                          {ctrl.finding_count}
                        </span>
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
                    <Td className="px-0 py-3 pr-4">
                      {ctrl.owner_label || ctrl.due_date ? (
                        <div className="flex flex-col gap-0.5">
                          {ctrl.owner_label && (
                            <span className="text-xs text-[var(--color-text-primary)]">
                              {ctrl.owner_label}
                            </span>
                          )}
                          {ctrl.due_date &&
                            (ctrl.overdue ? (
                              <span className="text-2xs text-[var(--color-severity-critical-text)]">
                                Overdue · {ctrl.due_date}
                              </span>
                            ) : (
                              <span className="text-2xs text-[var(--color-text-secondary)]">
                                Due {ctrl.due_date}
                              </span>
                            ))}
                        </div>
                      ) : (
                        <span className="text-[var(--color-text-secondary)]">—</span>
                      )}
                    </Td>
                    <Td className="px-0 py-3 text-right">
                      <span
                        aria-hidden="true"
                        className="text-[var(--color-text-tertiary)] transition-transform group-hover:translate-x-0.5 group-hover:text-[var(--color-text-secondary)]"
                      >
                        ›
                      </span>
                    </Td>
                  </Tr>
                )
              }),
            ]
          })}
        </Tbody>
      </Table>
    </div>
  )
}
