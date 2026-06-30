"use client"

import { useEffect, useState } from "react"

import { Input } from "@/components/ui/Input"
import { Sheet } from "@/components/ui/Sheet"
import {
  createMapping,
  searchMappableFindings,
  type MappableFinding,
} from "@/lib/client/compliance-api"

const SEARCH_DEBOUNCE_MS = 200

const SEVERITY_DOT: Record<string, string> = {
  critical: "bg-[var(--color-severity-critical)]",
  high: "bg-[var(--color-severity-high)]",
  medium: "bg-[var(--color-severity-medium)]",
  low: "bg-[var(--color-severity-low)]",
}

function findingLabel(f: MappableFinding): string {
  if (f.title && f.title.trim()) return f.title
  const key = f.identity_key.length > 80 ? `${f.identity_key.slice(0, 80)}…` : f.identity_key
  return `${f.tool}: ${key}`
}

function sourceLabel(f: MappableFinding): string | null {
  if (!f.org) return null
  return f.repo ? `${f.org}/${f.repo}` : f.org
}

/** Drawer that searches open, in-scope findings and links a chosen one to the
 * control — the manual counterpart to the auto-mapper. */
export function AddMappingSheet({
  open,
  framework,
  controlId,
  onClose,
  onAdded,
}: {
  open: boolean
  framework: string
  controlId: string
  onClose: () => void
  onAdded: () => void
}) {
  const [query, setQuery] = useState("")
  const [results, setResults] = useState<MappableFinding[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [addingId, setAddingId] = useState<number | null>(null)

  useEffect(() => {
    if (open) {
      setQuery("")
      setError(null)
      setAddingId(null)
      // The sheet stays mounted between opens; drop the previous candidate list
      // so a just-mapped finding doesn't flash before the fresh search resolves.
      setResults([])
    }
  }, [open])

  useEffect(() => {
    if (!open) return
    let cancelled = false
    setLoading(true)
    const handle = setTimeout(async () => {
      try {
        const found = await searchMappableFindings(framework, controlId, query || null, 20)
        if (!cancelled) setResults(found)
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : "Failed to search findings")
          setResults([])
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }, SEARCH_DEBOUNCE_MS)
    return () => {
      cancelled = true
      clearTimeout(handle)
    }
  }, [open, query, framework, controlId])

  async function handleAdd(f: MappableFinding) {
    setAddingId(f.id)
    setError(null)
    try {
      await createMapping(framework, controlId, f.id)
      onAdded()
      onClose()
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to add mapping")
      setAddingId(null)
    }
  }

  return (
    <Sheet
      open={open}
      onClose={onClose}
      title="Map a finding"
      description="Search open findings and link one the auto-mapper missed to this control."
      size="md"
    >
      <Input
        size="sm"
        type="search"
        autoFocus
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search by title or identity key"
        maxLength={255}
        className="mb-3"
      />

      {error && (
        <p
          role="alert"
          className="mb-3 rounded-md border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-3 py-2 text-xs text-[var(--color-severity-critical)]"
        >
          {error}
        </p>
      )}

      {loading && (
        <p className="px-1 py-2 text-sm text-[var(--color-text-secondary)]">Searching…</p>
      )}

      {!loading && !error && results.length === 0 && (
        <p className="px-1 py-8 text-center text-sm text-[var(--color-text-secondary)]">
          No open findings available to map.
        </p>
      )}

      <ul className="divide-y divide-[var(--color-border)]" role="listbox" aria-label="Mappable findings">
        {results.map((f) => {
          const source = sourceLabel(f)
          const dot = SEVERITY_DOT[f.severity ?? ""] ?? "bg-[var(--color-text-tertiary)]"
          const adding = addingId === f.id
          return (
            <li key={f.id}>
              <button
                type="button"
                role="option"
                aria-selected={false}
                disabled={addingId !== null}
                onClick={() => void handleAdd(f)}
                className="flex w-full items-start justify-between gap-3 py-2.5 text-left transition-colors hover:bg-[var(--color-surface-raised)] disabled:opacity-60"
              >
                <span className="min-w-0 flex-1">
                  <span className="flex items-center gap-2">
                    <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${dot}`} aria-hidden />
                    <span className="truncate text-sm font-medium text-[var(--color-text-primary)]">
                      {findingLabel(f)}
                    </span>
                  </span>
                  <span className="mt-0.5 block pl-3.5 text-[11px] text-[var(--color-text-secondary)]">
                    {f.tool}
                    {source ? ` · ${source}` : ""}
                  </span>
                </span>
                <span className="shrink-0 pt-0.5 text-xs font-semibold text-[var(--color-accent)]">
                  {adding ? "Adding…" : "Add"}
                </span>
              </button>
            </li>
          )
        })}
      </ul>
    </Sheet>
  )
}
