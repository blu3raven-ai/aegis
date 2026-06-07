"use client"

import { useEffect, useRef, useState } from "react"

import { FindingAssigneePicker } from "./FindingAssigneePicker"

export interface FindingsMoreFiltersValues {
  cwe: string | null
  kev: boolean
  epssMin: number | null
  riskScoreMin: number | null
  assigneeUserId: string | null
}

export interface FindingsMoreFiltersPopoverProps {
  values: FindingsMoreFiltersValues
  onChange: (next: Partial<FindingsMoreFiltersValues>) => void
}

function countActive(v: FindingsMoreFiltersValues): number {
  let n = 0
  if (v.cwe) n++
  if (v.kev) n++
  if (v.epssMin != null) n++
  if (v.riskScoreMin != null) n++
  if (v.assigneeUserId) n++
  return n
}

export function FindingsMoreFiltersPopover({ values, onChange }: FindingsMoreFiltersPopoverProps) {
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const activeCount = countActive(values)

  useEffect(() => {
    if (!open) return
    const onClick = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        setOpen(false)
      }
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
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        aria-expanded={open}
        className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-1 text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-border-strong)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
      >
        + More filters{activeCount > 0 ? ` (${activeCount})` : ""}
      </button>
      {open && (
        <div
          role="dialog"
          aria-label="More filters"
          className="absolute left-0 top-full z-50 mt-1 w-72 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-3 shadow-lg"
        >
          <div className="flex flex-col gap-3">
            <label className="flex items-center gap-2 text-xs text-[var(--color-text-secondary)]">
              <input
                type="checkbox"
                checked={values.kev}
                onChange={(e) => onChange({ kev: e.target.checked })}
                className="h-3.5 w-3.5 accent-[var(--color-accent)]"
              />
              CISA KEV only
            </label>

            <label className="flex flex-col gap-1 text-xs text-[var(--color-text-secondary)]">
              CWE
              <input
                type="text"
                placeholder="CWE-502"
                value={values.cwe ?? ""}
                onChange={(e) => onChange({ cwe: e.target.value || null })}
                maxLength={32}
                className="rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-2 py-1 text-xs text-[var(--color-text-primary)]"
              />
            </label>

            <label className="flex flex-col gap-1 text-xs text-[var(--color-text-secondary)]">
              EPSS ≥
              <input
                type="number"
                step={0.05}
                min={0}
                max={1}
                value={values.epssMin ?? ""}
                onChange={(e) => onChange({ epssMin: e.target.value === "" ? null : Number(e.target.value) })}
                className="rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-2 py-1 text-xs text-[var(--color-text-primary)]"
              />
            </label>

            <label className="flex flex-col gap-1 text-xs text-[var(--color-text-secondary)]">
              Risk score ≥
              <input
                type="number"
                step={5}
                min={0}
                max={100}
                value={values.riskScoreMin ?? ""}
                onChange={(e) =>
                  onChange({ riskScoreMin: e.target.value === "" ? null : Number(e.target.value) })
                }
                className="rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-2 py-1 text-xs text-[var(--color-text-primary)]"
              />
            </label>

            <FindingAssigneePicker
              label="Assignee"
              value={values.assigneeUserId}
              onChange={(next) => onChange({ assigneeUserId: next })}
            />
          </div>
        </div>
      )}
    </div>
  )
}
