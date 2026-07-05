"use client"

import { useEffect, useRef, useState } from "react"

import { AGE_OPTIONS, type AgePresetKey } from "./FindingsAgeFilter"
import { SORT_OPTIONS, type SortKey } from "./FindingsSortDropdown"
import { Button } from "@/components/ui/Button"
import { Select } from "@/components/ui/Select"

export type GroupKey = "scanner" | "severity" | "repo" | "status"

export const GROUP_BY_OPTIONS: { label: string; value: GroupKey }[] = [
  { label: "Tool", value: "scanner" },
  { label: "Severity", value: "severity" },
  { label: "Repo", value: "repo" },
  { label: "Status", value: "status" },
]

export interface FindingsDisplayOverflowProps {
  groupBy: GroupKey
  sortKey: SortKey
  agePreset: AgePresetKey
  onGroupByChange: (next: GroupKey) => void
  onSortKeyChange: (next: SortKey) => void
  onAgePresetChange: (next: AgePresetKey) => void
}

export function FindingsDisplayOverflow({
  groupBy,
  sortKey,
  agePreset,
  onGroupByChange,
  onSortKeyChange,
  onAgePresetChange,
}: FindingsDisplayOverflowProps) {
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onClick = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false)
    }
    document.addEventListener("mousedown", onClick)
    document.addEventListener("keydown", onKey)
    return () => {
      document.removeEventListener("mousedown", onClick)
      document.removeEventListener("keydown", onKey)
    }
  }, [open])

  return (
    <div ref={rootRef} className="relative inline-block">
      <Button
        variant="secondary"
        size="sm"
        iconOnly
        onClick={() => setOpen((p) => !p)}
        aria-expanded={open}
        aria-label="Display options"
        leadingIcon={
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" aria-hidden>
            <circle cx="12" cy="5" r="1.4" />
            <circle cx="12" cy="12" r="1.4" />
            <circle cx="12" cy="19" r="1.4" />
          </svg>
        }
      />

      {open && (
        <div
          role="menu"
          aria-label="Display options"
          className="absolute right-0 top-full z-50 mt-1 w-64 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-2 shadow-lg"
        >
          <div className="mb-2 px-1 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
            Display
          </div>
          <DisplayRow label="Group by">
            <Select
              size="sm"
              value={groupBy}
              onChange={(e) => onGroupByChange(e.target.value as GroupKey)}
            >
              {GROUP_BY_OPTIONS.map((opt) => (
                <option key={opt.label} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </Select>
          </DisplayRow>
          <DisplayRow label="Sort">
            <Select
              size="sm"
              value={sortKey}
              onChange={(e) => onSortKeyChange(e.target.value as SortKey)}
            >
              {SORT_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </Select>
          </DisplayRow>
          <DisplayRow label="Age">
            <Select
              size="sm"
              value={agePreset}
              onChange={(e) => onAgePresetChange(e.target.value as AgePresetKey)}
            >
              {AGE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </Select>
          </DisplayRow>
        </div>
      )}
    </div>
  )
}

function DisplayRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="mb-2 flex items-center gap-3">
      <label className="w-16 shrink-0 text-2xs text-[var(--color-text-secondary)]">{label}</label>
      <div className="flex-1">{children}</div>
    </div>
  )
}
