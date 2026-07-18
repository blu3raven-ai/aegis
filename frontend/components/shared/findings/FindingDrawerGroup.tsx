"use client"

import { useCallback, useEffect, useState, type ReactNode } from "react"

/** Persist a drawer group's open/closed state per browser so an analyst's
 *  preferred layout survives across findings and sessions. Falls back to the
 *  default when storage is unavailable. */
function useGroupOpen(id: string, defaultOpen: boolean): [boolean, () => void] {
  const key = `aegis:finding-group:${id}`
  const [open, setOpen] = useState(defaultOpen)
  useEffect(() => {
    try {
      const saved = window.localStorage.getItem(key)
      if (saved !== null) setOpen(saved === "1")
    } catch {
      /* storage unavailable — keep the default */
    }
  }, [key])
  const toggle = useCallback(() => {
    setOpen((prev) => {
      const next = !prev
      try {
        window.localStorage.setItem(key, next ? "1" : "0")
      } catch {
        /* ignore */
      }
      return next
    })
  }, [key])
  return [open, toggle]
}

interface FindingDrawerGroupProps {
  /** Stable key for persistence (e.g. "analysis"). */
  id: string
  label: string
  defaultOpen?: boolean
  children: ReactNode
}

/**
 * Collapsible section group in the finding drawer. Reuses the app's list
 * group-header chrome — a section band with an uppercase label and a rotating
 * chevron — so the drawer chunks into scannable clusters (Overview / Analysis /
 * Remediation / Context) without introducing new styling. The body reapplies
 * the drawer's per-section padding + dividers, so grouped sections render
 * exactly as they did in the flat layout.
 */
export function FindingDrawerGroup({
  id,
  label,
  defaultOpen = true,
  children,
}: FindingDrawerGroupProps) {
  const [open, toggle] = useGroupOpen(id, defaultOpen)
  const regionId = `finding-group-${id}`
  return (
    <div>
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        aria-controls={regionId}
        className="flex w-full items-center gap-2 bg-[var(--color-bg-section)] px-5 py-2.5 text-left font-mono text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)] transition-colors hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-secondary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--color-accent)]"
      >
        <svg
          width="10"
          height="10"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.5"
          className={`shrink-0 transition-transform ${open ? "rotate-0" : "-rotate-90"}`}
          aria-hidden="true"
        >
          <path d="m6 9 6 6 6-6" />
        </svg>
        {label}
      </button>
      {open ? (
        <div
          id={regionId}
          className="divide-y divide-[var(--color-border-divider)] [&>*]:px-5 [&>*]:py-3.5"
        >
          {children}
        </div>
      ) : null}
    </div>
  )
}
