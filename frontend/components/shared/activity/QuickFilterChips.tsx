"use client"

import { useEffect, useRef, type ReactNode } from "react"
import { ActivityFilterChip } from "./ActivityFilterChip"
import { CHIP_GROUPS, eventTypeLabel } from "./event-labels"
import type { DayStats } from "@/lib/shared/activity-derivations"
import { Button } from "@/components/ui/Button"
import { FilterChip } from "@/components/ui/FilterChip"

const FILTER_GROUPS = [
  {
    label: "Findings",
    types: ["finding.created", "finding.fixed", "finding.dismissed", "finding.reopened"],
  },
  {
    label: "Scans",
    types: ["scan.completed", "scan.failed"],
  },
  {
    label: "Intel",
    types: ["intel.cve.added", "kev.added", "sla.breached"],
  },
  {
    label: "Integrations",
    types: ["integration.connected", "integration.disconnected"],
  },
]

interface FilterOverflowProps {
  activeTypes: string[]
  onToggle: (type: string) => void
  onClear: () => void
  open: boolean
  onOpenChange: (v: boolean) => void
}

export function FilterOverflow({
  activeTypes,
  onToggle,
  onClear,
  open,
  onOpenChange,
}: FilterOverflowProps) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        onOpenChange(false)
      }
    }
    document.addEventListener("mousedown", handleClick)
    return () => document.removeEventListener("mousedown", handleClick)
  }, [open, onOpenChange])

  return (
    <div className="relative shrink-0" ref={ref}>
      <Button
        variant="secondary"
        size="sm"
        onClick={() => onOpenChange(!open)}
        aria-label="More filters"
        aria-haspopup="true"
        aria-expanded={open}
        className="rounded-full"
        trailingIcon={
          activeTypes.length > 0 ? (
            <span className="rounded-full bg-[var(--color-accent)] px-1.5 py-px text-2xs font-bold text-[var(--color-accent-on)]">
              {activeTypes.length}
            </span>
          ) : undefined
        }
      >
        <span aria-hidden="true">…</span>
      </Button>

      {open && (
        <div className="absolute right-0 top-full z-10 mt-1 w-64 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-3 shadow-lg">
          {activeTypes.length > 0 && (
            <Button
              variant="ghost"
              size="xs"
              onClick={onClear}
              className="mb-2 w-full"
            >
              Clear all filters
            </Button>
          )}
          {FILTER_GROUPS.map((group) => (
            <div key={group.label} className="mb-3 last:mb-0">
              <p className="mb-1.5 px-1 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
                {group.label}
              </p>
              <div className="flex flex-wrap gap-1.5">
                {group.types.map((type) => (
                  <ActivityFilterChip
                    key={type}
                    label={eventTypeLabel(type)}
                    active={activeTypes.includes(type)}
                    onToggle={() => onToggle(type)}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

interface QuickFilterChipsProps {
  stats: DayStats | null
  activeChip: string | null
  onSelect: (chipId: string, types: string[]) => void
  overflow: ReactNode
}

export function QuickFilterChips({ stats, activeChip, onSelect, overflow }: QuickFilterChipsProps) {
  return (
    <div className="-mx-1 flex w-full items-center gap-2 overflow-x-auto px-1">
      {CHIP_GROUPS.map((chip) => {
        const isActive = activeChip === chip.id

        let count: number | undefined
        if (stats === null) {
          count = undefined
        } else if (chip.id === "all") {
          count = stats.total
        } else {
          count = chip.types.reduce((acc, t) => acc + (stats.byType[t] || 0), 0)
        }

        return (
          <FilterChip
            key={chip.id}
            label={chip.label}
            active={isActive}
            onClick={() => onSelect(chip.id, [...chip.types])}
            count={count}
            className="shrink-0"
          />
        )
      })}
      {overflow}
    </div>
  )
}
