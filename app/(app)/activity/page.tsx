"use client"

import { useState, useCallback, useEffect, useRef } from "react"
import { ActivityFeed } from "@/components/shared/activity/ActivityFeed"
import { ActivityFilterChip, eventTypeLabel } from "@/components/shared/activity/ActivityFilterChip"
import { PageHeader } from "@/components/layout/PageHeader"
import { ActivityIcon } from "@/lib/shared/ui/page-icons"
import { listActivity, listActivityTypes } from "@/lib/client/activity-api"
import type { ActivityEvent } from "@/lib/client/activity-api"

// ── Filter dropdown ───────────────────────────────────────────────────────────

// Curated groups shown in the filter dropdown (not all types at once).
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

interface FilterDropdownProps {
  activeTypes: string[]
  onToggle: (type: string) => void
  onClear: () => void
  open: boolean
  onOpenChange: (v: boolean) => void
}

function FilterDropdown({ activeTypes, onToggle, onClear, open, onOpenChange }: FilterDropdownProps) {
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
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => onOpenChange(!open)}
        className="flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-sm text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-text-primary)]"
      >
        <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M3 6h18M7 12h10M11 18h2" />
        </svg>
        Filter
        {activeTypes.length > 0 && (
          <span className="rounded-full bg-[var(--color-accent)] px-1.5 py-px text-2xs font-bold text-[var(--color-accent-on)]">
            {activeTypes.length}
          </span>
        )}
        <svg className={`h-3.5 w-3.5 transition-transform ${open ? "rotate-180" : ""}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="m6 9 6 6 6-6" />
        </svg>
      </button>

      {open && (
        <div className="absolute right-0 top-full z-10 mt-1 w-64 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-3 shadow-lg">
          {activeTypes.length > 0 && (
            <button
              type="button"
              onClick={onClear}
              className="mb-2 w-full rounded-lg py-1 text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            >
              Clear all filters
            </button>
          )}
          {FILTER_GROUPS.map((group) => (
            <div key={group.label} className="mb-3 last:mb-0">
              <p className="mb-1.5 px-1 text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
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

// ── Page ──────────────────────────────────────────────────────────────────────

export default function ActivityPage() {
  const [events, setEvents] = useState<ActivityEvent[]>([])
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [activeTypes, setActiveTypes] = useState<string[]>([])
  const [filterOpen, setFilterOpen] = useState(false)
  const [refreshing, setRefreshing] = useState(false)

  const fetchEvents = useCallback(async (types: string[], cursor?: string) => {
    try {
      const params = {
        limit: 50,
        ...(types.length > 0 ? { types } : {}),
        ...(cursor ? { cursor } : {}),
      }
      const resp = await listActivity(params)
      return resp
    } catch (err) {
      throw err
    }
  }, [])

  const load = useCallback(async (types: string[]) => {
    setLoading(true)
    setError(null)
    try {
      const resp = await fetchEvents(types)
      setEvents(resp.events)
      setNextCursor(resp.next_cursor)
    } catch {
      setError("Failed to load activity. Please try again.")
    } finally {
      setLoading(false)
    }
  }, [fetchEvents])

  useEffect(() => {
    load(activeTypes)
  }, [activeTypes, load])

  const handleRefresh = useCallback(async () => {
    setRefreshing(true)
    try {
      const resp = await fetchEvents(activeTypes)
      setEvents(resp.events)
      setNextCursor(resp.next_cursor)
    } catch {
      // Silently fail on refresh — existing data stays
    } finally {
      setRefreshing(false)
    }
  }, [fetchEvents, activeTypes])

  const handleLoadMore = useCallback(async () => {
    if (!nextCursor || loadingMore) return
    setLoadingMore(true)
    try {
      const resp = await fetchEvents(activeTypes, nextCursor)
      setEvents((prev) => [...prev, ...resp.events])
      setNextCursor(resp.next_cursor)
    } catch {
      // Silently fail on load-more — user can retry by clicking again
    } finally {
      setLoadingMore(false)
    }
  }, [nextCursor, loadingMore, fetchEvents, activeTypes])

  const handleTypeToggle = useCallback((type: string) => {
    setActiveTypes((prev) =>
      prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type]
    )
  }, [])

  const handleClearFilters = useCallback(() => {
    setActiveTypes([])
  }, [])

  return (
    <div className="flex h-full flex-col bg-[var(--color-bg)]">
      <PageHeader
        icon={<ActivityIcon />}
        title="Activity"
        description="What's happened across your org recently."
        controls={
          <div className="flex items-center gap-2">
            <FilterDropdown
              activeTypes={activeTypes}
              onToggle={handleTypeToggle}
              onClear={handleClearFilters}
              open={filterOpen}
              onOpenChange={setFilterOpen}
            />
            <button
              type="button"
              onClick={handleRefresh}
              disabled={refreshing || loading}
              title="Refresh"
              className="flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-sm text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-text-primary)] disabled:opacity-50"
            >
              <svg
                className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`}
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth={2}
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <path d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0 3.181 3.183a8.25 8.25 0 0 0 13.803-3.7M4.031 9.865a8.25 8.25 0 0 1 13.803-3.7l3.181 3.182m0-4.991v4.99" />
              </svg>
              Refresh
            </button>
          </div>
        }
      />

      <div className="mx-auto w-full max-w-3xl px-4 py-6">
      {/* Active type chips */}
      {activeTypes.length > 0 && (
        <div className="mb-4 flex flex-wrap gap-2">
          {activeTypes.map((type) => (
            <ActivityFilterChip
              key={type}
              label={eventTypeLabel(type)}
              active
              onToggle={() => handleTypeToggle(type)}
            />
          ))}
          <button
            type="button"
            onClick={handleClearFilters}
            className="text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] underline"
          >
            Clear
          </button>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="mb-4 rounded-lg border border-[var(--color-severity-high)]/30 bg-[var(--color-severity-high)]/5 px-4 py-3 text-sm text-[var(--color-severity-high)]">
          {error}
        </div>
      )}

      {/* Feed */}
      <ActivityFeed
        events={events}
        loading={loading}
        hasMore={nextCursor !== null}
        onLoadMore={handleLoadMore}
        loadingMore={loadingMore}
      />
      </div>
    </div>
  )
}
