"use client"

import { useEffect, useState } from "react"
import Link from "next/link"

import { getFindingRelated, type FindingRelated } from "@/lib/client/findings-api"

const SEV_DOT: Record<string, string> = {
  critical: "var(--color-severity-critical)",
  high: "var(--color-severity-high)",
  medium: "var(--color-severity-medium)",
  low: "var(--color-severity-low)",
}

/**
 * Blast-radius line for the drawer: "Also affects N other repositories",
 * expandable to the actual list (lazily fetched), each row deep-linking to that
 * repo's finding. Renders nothing when the count is zero/unknown.
 */
export function BlastRadiusSection({
  findingId,
  count,
}: {
  findingId: number
  count: number | undefined
}) {
  const [open, setOpen] = useState(false)
  const [rows, setRows] = useState<FindingRelated[] | null>(null)
  const [loading, setLoading] = useState(false)

  // Collapse + drop the cached list when the drawer moves to another finding.
  useEffect(() => {
    setOpen(false)
    setRows(null)
  }, [findingId])

  if (count == null || count <= 0) return null

  async function toggle() {
    const next = !open
    setOpen(next)
    if (next && rows === null && !loading) {
      setLoading(true)
      try {
        setRows(await getFindingRelated(findingId))
      } finally {
        setLoading(false)
      }
    }
  }

  return (
    <div className="text-xs">
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        className="flex items-center gap-1.5 text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)]"
      >
        <svg viewBox="0 0 24 24" className="h-3.5 w-3.5 shrink-0" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M3 7v10a2 2 0 0 0 2 2h14M3 7l9-4 9 4M3 7l9 4 9-4" />
        </svg>
        Also affects{" "}
        <span className="font-semibold text-[var(--color-text-primary)]">{count}</span> other{" "}
        {count === 1 ? "repository" : "repositories"}
        <svg
          viewBox="0 0 24 24"
          className={`h-3.5 w-3.5 shrink-0 transition-transform ${open ? "rotate-180" : ""}`}
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="M6 9l6 6 6-6" />
        </svg>
      </button>

      {open && (
        <ul className="mt-2 space-y-1 border-l border-[var(--color-border)] pl-3">
          {loading && <li className="text-[var(--color-text-tertiary)]">Loading…</li>}
          {rows?.map((r) => (
            <li key={r.finding_id}>
              <Link
                href={`/findings?finding=${r.finding_id}`}
                className="flex items-center gap-2 transition-colors hover:text-[var(--color-accent)]"
              >
                <span
                  className="h-1.5 w-1.5 shrink-0 rounded-full"
                  style={{ background: SEV_DOT[r.severity ?? ""] ?? "var(--color-text-tertiary)" }}
                  aria-hidden="true"
                />
                <span className="truncate font-mono text-[var(--color-text-secondary)]">{r.repo}</span>
              </Link>
            </li>
          ))}
          {rows && rows.length === 0 && !loading && (
            <li className="text-[var(--color-text-tertiary)]">No accessible repositories</li>
          )}
        </ul>
      )}
    </div>
  )
}
