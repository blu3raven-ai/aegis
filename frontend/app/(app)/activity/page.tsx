"use client"

import { useState, useCallback, useEffect, useRef, type ReactNode } from "react"
import { ActivityFeed } from "@/components/shared/activity/ActivityFeed"
import { ActivityFilterChip, eventTypeLabel } from "@/components/shared/activity/ActivityFilterChip"
import { PageHeader } from "@/components/layout/PageHeader"
import { ActivityIcon } from "@/lib/shared/ui/page-icons"
import { KpiCard } from "@/components/shared/KpiCard"
import { listActivity } from "@/lib/client/activity-api"
import type { ActivityEvent } from "@/lib/client/activity-api"
import { CHIP_GROUPS } from "@/components/shared/activity/event-labels"
import { relativeTime } from "@/lib/shared/relative-time"

const NEUTRAL = "text-[var(--color-text-primary)]"
const CRITICAL = "text-[var(--color-severity-critical)]"
const OK = "text-[var(--color-state-fixed)]"

function chipTypesFor(chipId: string | null): string[] {
  if (!chipId) return []
  const group = CHIP_GROUPS.find((c) => c.id === chipId)
  return group ? [...group.types] : []
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface DayStats {
  total: number
  newFindings: number
  criticalFindings: number
  fixed: number
  decisions: number
  scans: number
  byType: Record<string, number>
}

interface CatchUpData {
  since: string
  total: number
  newFindings: number
  criticalFindings: number
  fixed: number
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function deriveDayStats(events: ActivityEvent[]): DayStats {
  const byType: Record<string, number> = {}
  for (const e of events) {
    byType[e.type] = (byType[e.type] || 0) + 1
  }
  return {
    total: events.length,
    newFindings: events.filter((e) => e.type === "finding.created").length,
    criticalFindings: events.filter(
      (e) => e.type === "finding.created" && e.payload.severity === "critical"
    ).length,
    fixed: events.filter((e) => e.type === "finding.fixed").length,
    decisions: events.filter((e) => e.type === "finding.dismissed").length,
    scans: events.filter((e) => e.type === "scan.completed").length,
    byType,
  }
}

function deriveCatchUp(events: ActivityEvent[], since: string): CatchUpData {
  return {
    since,
    total: events.length,
    newFindings: events.filter((e) => e.type === "finding.created").length,
    criticalFindings: events.filter(
      (e) => e.type === "finding.created" && e.payload.severity === "critical"
    ).length,
    fixed: events.filter((e) => e.type === "finding.fixed").length,
  }
}

// ── Filter overflow dropdown ──────────────────────────────────────────────────

// Curated groups shown in the overflow dropdown (more granular than the chip row).
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

function FilterOverflow({ activeTypes, onToggle, onClear, open, onOpenChange }: FilterOverflowProps) {
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
      <button
        type="button"
        onClick={() => onOpenChange(!open)}
        aria-label="More filters"
        aria-haspopup="true"
        aria-expanded={open}
        className="inline-flex items-center gap-1.5 rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-sm text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)]"
      >
        <span aria-hidden="true">…</span>
        {activeTypes.length > 0 && (
          <span className="rounded-full bg-[var(--color-accent)] px-1.5 py-px text-2xs font-bold text-[var(--color-accent-on)]">
            {activeTypes.length}
          </span>
        )}
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

// ── StatStrip ─────────────────────────────────────────────────────────────────

interface StatStripProps {
  stats: DayStats | null
  errored: boolean
}

function StatStrip({ stats, errored }: StatStripProps) {
  const isEmpty = stats === null
  const placeholder = errored ? "Stats unavailable" : "Loading…"

  const events = isEmpty ? "—" : stats.total.toLocaleString()
  const newFindings = isEmpty ? "—" : stats.newFindings.toLocaleString()
  const fixed = isEmpty ? "—" : stats.fixed.toLocaleString()
  const decisions = isEmpty ? "—" : stats.decisions.toLocaleString()
  const scans = isEmpty ? "—" : stats.scans.toLocaleString()

  return (
    <div className="grid grid-cols-2 gap-3 border-b border-[var(--color-border-divider)] bg-[var(--color-surface)] px-5 py-4 sm:grid-cols-3 lg:grid-cols-5">
      <KpiCard
        label="Events 24h"
        value={events}
        note={isEmpty ? placeholder : "All event types"}
        valueClass={NEUTRAL}
      />
      <KpiCard
        label="New findings"
        value={newFindings}
        note={
          isEmpty
            ? placeholder
            : stats.criticalFindings > 0
              ? `${stats.criticalFindings} critical`
              : "No criticals in window"
        }
        valueClass={isEmpty ? NEUTRAL : stats.criticalFindings > 0 ? CRITICAL : NEUTRAL}
      />
      <KpiCard
        label="Fixed"
        value={fixed}
        note={isEmpty ? placeholder : "Marked fixed in window"}
        valueClass={isEmpty ? NEUTRAL : stats.fixed > 0 ? OK : NEUTRAL}
      />
      <KpiCard
        label="Decisions"
        value={decisions}
        note={isEmpty ? placeholder : "Dismissed findings"}
        valueClass={NEUTRAL}
      />
      <KpiCard
        label="Scans"
        value={scans}
        note={isEmpty ? placeholder : "Completed scans"}
        valueClass={NEUTRAL}
      />
    </div>
  )
}

// ── CatchUpBanner ─────────────────────────────────────────────────────────────

interface CatchUpBannerProps {
  data: CatchUpData
  onDismiss: () => void
}

function CatchUpBanner({ data, onDismiss }: CatchUpBannerProps) {
  const eventLabel = `${data.total} event${data.total === 1 ? "" : "s"}`
  return (
    <div className="mb-4 flex items-center gap-3.5 rounded-xl border border-[color-mix(in_srgb,var(--color-accent)_22%,transparent)] bg-gradient-to-br from-[color-mix(in_srgb,var(--color-accent)_8%,transparent)] to-[color-mix(in_srgb,#a78bfa_5%,transparent)] px-4 py-3.5">
      {/* Icon — mock catchup-icon (accent square with clock svg) */}
      <span
        aria-hidden="true"
        className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-[var(--color-accent)] text-[var(--color-accent-on)]"
      >
        <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <path d="M12 6v6l4 2" />
        </svg>
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold text-[var(--color-text-primary)]">
          You&apos;ve been away since {relativeTime(data.since)}
        </p>
        <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
          <strong className="font-semibold text-[var(--color-text-primary)]">{eventLabel}</strong>
          {data.newFindings > 0 && (
            <>
              {" · "}
              <strong className="font-semibold text-[var(--color-text-primary)]">
                {data.newFindings} new finding{data.newFindings === 1 ? "" : "s"}
              </strong>
              {data.criticalFindings > 0 && <> ({data.criticalFindings} critical)</>}
            </>
          )}
          {data.fixed > 0 && (
            <>
              {" · "}
              <strong className="font-semibold text-[var(--color-text-primary)]">
                {data.fixed} fixed
              </strong>
            </>
          )}
        </p>
      </div>
      <button
        type="button"
        onClick={onDismiss}
        aria-label="Dismiss catch-up banner"
        className="shrink-0 rounded-md p-1 text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface)] hover:text-[var(--color-text-primary)]"
      >
        <svg
          className="h-4 w-4"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="M18 6 6 18M6 6l12 12" />
        </svg>
      </button>
    </div>
  )
}

// ── QuickFilterChips ──────────────────────────────────────────────────────────

interface QuickFilterChipsProps {
  stats: DayStats | null
  activeChip: string | null
  onSelect: (chipId: string, types: string[]) => void
  overflow: ReactNode
}

function QuickFilterChips({ stats, activeChip, onSelect, overflow }: QuickFilterChipsProps) {
  return (
    <div className="-mx-1 flex w-full items-center gap-2 overflow-x-auto px-1">
      {CHIP_GROUPS.map((chip) => {
        const isActive = activeChip === chip.id

        // Compute count: for "all" show total, for others count matching types
        let count: string | null
        if (stats === null) {
          count = null
        } else if (chip.id === "all") {
          count = String(stats.total)
        } else {
          const n = chip.types.reduce((acc, t) => acc + (stats.byType[t] || 0), 0)
          count = String(n)
        }

        const baseClasses =
          "inline-flex shrink-0 items-center gap-1.5 rounded-full px-3 py-1.5 text-sm transition-colors"
        const activeClasses =
          "bg-[var(--color-accent)] text-[var(--color-accent-on)]"
        const inactiveClasses =
          "border border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"

        const className = [
          baseClasses,
          isActive ? activeClasses : inactiveClasses,
        ].join(" ")

        return (
          <button
            key={chip.id}
            type="button"
            className={className}
            onClick={() => onSelect(chip.id, [...chip.types])}
          >
            {chip.label}
            {count !== null && <span className="opacity-70 tabular-nums">{count}</span>}
          </button>
        )
      })}
      {overflow}
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
  const [activeTypes, setActiveTypes] = useState<string[]>(() => chipTypesFor("all"))
  const [filterOpen, setFilterOpen] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [stats, setStats] = useState<DayStats | null>(null)
  const [statsError, setStatsError] = useState(false)
  const [catchUp, setCatchUp] = useState<CatchUpData | null>(null)
  const [catchUpDismissed, setCatchUpDismissed] = useState(false)
  // null = dropdown in custom-filter mode (no chip group matches the active set)
  const [activeChip, setActiveChip] = useState<string | null>("all")

  // Fetch 24h stats and conditionally fetch catch-up data on mount
  useEffect(() => {
    const dayAgo = new Date(Date.now() - 24 * 3600_000).toISOString()
    listActivity({ since: dayAgo, limit: 200 })
      .then(({ events: e }) => setStats(deriveDayStats(e)))
      .catch(() => setStatsError(true))

    // localStorage can throw in private browsing modes; the catch-up banner is non-essential
    try {
      const last = localStorage.getItem("activity:last-seen")
      const today = new Date().toISOString().slice(0, 10)
      const dismissedToday =
        localStorage.getItem(`activity:catchup-dismissed:${today}`) === "1"

      if (
        last &&
        Date.now() - new Date(last).getTime() > 24 * 3600_000 &&
        !dismissedToday
      ) {
        listActivity({ since: last, limit: 500 })
          .then(({ events: e }) => setCatchUp(deriveCatchUp(e, last)))
          .catch(() => setCatchUp(null))
      }

      localStorage.setItem("activity:last-seen", new Date().toISOString())
    } catch {
      // Storage unavailable — skip the catch-up banner this session
    }
  }, [])

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
    // When the user manually toggles types via dropdown, no chip is active
    setActiveChip(null)
    setActiveTypes((prev) =>
      prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type]
    )
  }, [])

  const handleClearFilters = useCallback(() => {
    setActiveTypes([])
    setActiveChip("all")
  }, [])

  const handleChipSelect = useCallback((chipId: string, types: string[]) => {
    setActiveChip(chipId)
    setActiveTypes(types)
  }, [])

  const handleDismissBanner = useCallback(() => {
    setCatchUpDismissed(true)
    try {
      const today = new Date().toISOString().slice(0, 10)
      localStorage.setItem(`activity:catchup-dismissed:${today}`, "1")
    } catch {
      // Storage unavailable — banner stays dismissed for the session only
    }
  }, [])

  const showCatchUp = catchUp !== null && !catchUpDismissed

  return (
    <div className="flex h-full flex-col bg-[var(--color-bg)]">
      <PageHeader
        icon={<ActivityIcon />}
        title="Activity"
        description="What's happened across your org recently."
        controls={
          <div className="flex items-center gap-2">
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

      {/* Stat strip — flush below the header, full width, mirrors the Inbox layout */}
      <StatStrip stats={stats} errored={statsError} />

      {/* Quick filter chips — own strip below stats, mirrors the Inbox filter bar */}
      <div className="flex flex-wrap items-center gap-2 border-b border-[var(--color-border-divider)] bg-[var(--color-surface)] px-5 py-2.5">
        <QuickFilterChips
          stats={stats}
          activeChip={activeChip}
          onSelect={handleChipSelect}
          overflow={
            <FilterOverflow
              activeTypes={activeTypes}
              onToggle={handleTypeToggle}
              onClear={handleClearFilters}
              open={filterOpen}
              onOpenChange={setFilterOpen}
            />
          }
        />
      </div>

      {/* Active type chips — own strip below the filter bar, mirrors the inbox FilterTag row */}
      {activeChip === null && activeTypes.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 border-b border-[var(--color-border-divider)] bg-[var(--color-surface)] px-5 py-2.5">
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

      <div className="mx-auto w-full max-w-3xl px-4 py-6">
        {/* Catch-up banner — shown when user has been away for >24h */}
        {showCatchUp && (
          <CatchUpBanner data={catchUp} onDismiss={handleDismissBanner} />
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
