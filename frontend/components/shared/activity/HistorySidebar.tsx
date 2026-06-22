"use client"

import type { DayStats } from "@/lib/shared/activity-derivations"

// Mirrors the Triage InboxQueueSidebar chrome so the two Inbox tabs share one
// shell. Rows are single-select event filters (like Triage's queues); counts
// come from the 24h day-stats.

interface FilterRow {
  id: string
  label: string
  iconPath: string
  types: string[]
}

interface FilterSection {
  label: string
  rows: FilterRow[]
}

const SECTIONS: FilterSection[] = [
  {
    label: "Activity",
    rows: [
      { id: "all", label: "All activity", iconPath: "M4 6h16M4 12h16M4 18h16", types: [] },
    ],
  },
  {
    label: "Findings",
    rows: [
      { id: "created", label: "New findings", iconPath: "M12 4.5v15m7.5-7.5h-15", types: ["finding.created"] },
      { id: "fixed", label: "Fixed", iconPath: "M4.5 12.75l6 6 9-13.5", types: ["finding.fixed"] },
      { id: "reopened", label: "Reopened", iconPath: "M4 9a8 8 0 0 1 13.66-3.66M20 4v5h-5M20 15a8 8 0 0 1-13.66 3.66M4 20v-5h5", types: ["finding.reopened"] },
      { id: "dismissed", label: "Dismissed", iconPath: "M6 7h12M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2m-8 0 .8 12a1 1 0 0 0 1 .94h6.4a1 1 0 0 0 1-.94L17 7", types: ["finding.dismissed"] },
    ],
  },
  {
    label: "Scans",
    rows: [
      { id: "completed", label: "Completed", iconPath: "M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z", types: ["scan.completed"] },
      { id: "failed", label: "Failed", iconPath: "M9.75 9.75l4.5 4.5m0-4.5l-4.5 4.5M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z", types: ["scan.failed"] },
      { id: "cancelled", label: "Cancelled", iconPath: "M18.364 18.364A9 9 0 0 0 5.636 5.636m12.728 12.728A9 9 0 0 1 5.636 5.636m12.728 12.728L5.636 5.636", types: ["scan.cancelled"] },
    ],
  },
]

function rowCount(types: string[], stats: DayStats | null): string | null {
  if (!stats) return null
  const n = types.length === 0 ? stats.total : types.reduce((acc, t) => acc + (stats.byType[t] || 0), 0)
  return n.toLocaleString()
}

function sameTypes(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false
  const setB = new Set(b)
  return a.every((t) => setB.has(t))
}

function FilterIcon({ d }: { d: string }) {
  return (
    <svg
      className="h-3.5 w-3.5 shrink-0"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={d} />
    </svg>
  )
}

interface HistorySidebarProps {
  activeTypes: string[]
  stats: DayStats | null
  onSelect: (types: string[]) => void
}

export function HistorySidebar({ activeTypes, stats, onSelect }: HistorySidebarProps) {
  return (
    <aside
      aria-label="Activity filters"
      className="hidden md:flex w-[220px] shrink-0 flex-col border-r border-[var(--color-border)] bg-[var(--color-surface)] overflow-y-auto pt-3"
    >
      {SECTIONS.map((section, i) => (
        <div key={section.label}>
          {i > 0 && <div className="mx-3 border-t border-[var(--color-border)]" />}
          <div className="px-2 pb-3">
            <div className="px-2.5 pb-1 pt-2 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
              {section.label}
            </div>
            <div className="flex flex-col gap-0.5">
              {section.rows.map((row) => {
                const active = sameTypes(activeTypes, row.types)
                const count = rowCount(row.types, stats)
                return (
                  <button
                    key={row.id}
                    type="button"
                    onClick={() => onSelect(row.types)}
                    aria-pressed={active}
                    className={`relative flex w-full items-center gap-2 rounded-md px-2.5 py-1.5 text-left text-[13px] transition-colors ${
                      active
                        ? "bg-[var(--color-accent-subtle)] font-medium text-[var(--color-text-primary)]"
                        : "text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
                    }`}
                  >
                    {active && (
                      <span
                        aria-hidden="true"
                        className="absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-full bg-[var(--color-accent)]"
                      />
                    )}
                    <span className={active ? "text-[var(--color-accent)]" : ""}>
                      <FilterIcon d={row.iconPath} />
                    </span>
                    <span className="flex-1 truncate">{row.label}</span>
                    {count !== null && (
                      <span
                        className={`shrink-0 rounded-full px-1.5 py-0.5 text-[11px] font-medium tabular-nums ${
                          active
                            ? "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
                            : "bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]"
                        }`}
                      >
                        {count}
                      </span>
                    )}
                  </button>
                )
              })}
            </div>
          </div>
        </div>
      ))}
    </aside>
  )
}
