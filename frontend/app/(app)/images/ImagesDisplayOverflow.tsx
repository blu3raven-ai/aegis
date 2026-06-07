"use client"

import { useEffect, useRef, useState } from "react"

export type ImagesSortMode = "critical" | "last-scan" | "name"

const SORT_LABELS: Record<ImagesSortMode, string> = {
  critical: "Critical first",
  "last-scan": "Last scan",
  name: "A–Z",
}

export interface ImagesDisplayOverflowProps {
  sort: ImagesSortMode
  onSortChange: (next: ImagesSortMode) => void
}

export function ImagesDisplayOverflow({ sort, onSortChange }: ImagesDisplayOverflowProps) {
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
      <button
        type="button"
        onClick={() => setOpen((p) => !p)}
        aria-expanded={open}
        aria-label="Display options"
        className="inline-grid h-8 w-8 place-items-center rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:border-[var(--color-border-strong)] hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
      >
        <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" aria-hidden>
          <circle cx="12" cy="5" r="1.4" />
          <circle cx="12" cy="12" r="1.4" />
          <circle cx="12" cy="19" r="1.4" />
        </svg>
      </button>
      {open && (
        <div
          role="menu"
          aria-label="Display options"
          className="absolute right-0 top-full z-50 mt-1 w-56 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-2 shadow-lg"
        >
          <div className="mb-2 px-1 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
            Display
          </div>
          <div className="flex items-center gap-3 px-1 py-1">
            <label htmlFor="images-sort" className="w-12 shrink-0 text-2xs text-[var(--color-text-secondary)]">
              Sort
            </label>
            <select
              id="images-sort"
              value={sort}
              onChange={(e) => onSortChange(e.target.value as ImagesSortMode)}
              className="flex-1 rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-2 py-1 text-xs text-[var(--color-text-primary)] focus:outline-none focus-visible:border-[var(--color-accent)]"
            >
              {(Object.keys(SORT_LABELS) as ImagesSortMode[]).map((s) => (
                <option key={s} value={s}>
                  {SORT_LABELS[s]}
                </option>
              ))}
            </select>
          </div>
        </div>
      )}
    </div>
  )
}
