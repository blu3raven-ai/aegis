"use client"

import { useState, useCallback, useEffect } from "react"
import { ActivityFeed } from "@/components/shared/activity/ActivityFeed"
import { ActivityFilterChip, eventTypeLabel } from "@/components/shared/activity/ActivityFilterChip"
import { CatchUpBanner } from "@/components/shared/activity/CatchUpBanner"
import { QuickFilterChips, FilterOverflow } from "@/components/shared/activity/QuickFilterChips"
import { PageHeader } from "@/components/layout/PageHeader"
import { ActivityIcon } from "@/lib/shared/ui/page-icons"
import { KpiCard } from "@/components/shared/KpiCard"
import { Button } from "@/components/ui/Button"
import { listActivity } from "@/lib/client/activity-api"
import type { ActivityEvent } from "@/lib/client/activity-api"
import { chipTypesFor } from "@/components/shared/activity/event-labels"
import {
  deriveCatchUp,
  deriveDayStats,
  type CatchUpData,
  type DayStats,
} from "@/lib/shared/activity-derivations"

const NEUTRAL = "text-[var(--color-text-primary)]"
const CRITICAL = "text-[var(--color-severity-critical)]"
const OK = "text-[var(--color-state-fixed)]"

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

  const load = useCallback(async (types: string[]) => {
    setLoading(true)
    setError(null)
    try {
      const resp = await listActivity({
        limit: 50,
        ...(types.length > 0 ? { types } : {}),
      })
      setEvents(resp.events)
      setNextCursor(resp.next_cursor)
    } catch {
      setError("Failed to load activity. Please try again.")
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load(activeTypes)
  }, [activeTypes, load])

  const handleRefresh = useCallback(async () => {
    setRefreshing(true)
    try {
      const resp = await listActivity({
        limit: 50,
        ...(activeTypes.length > 0 ? { types: activeTypes } : {}),
      })
      setEvents(resp.events)
      setNextCursor(resp.next_cursor)
    } catch {
      // Silently fail on refresh — existing data stays
    } finally {
      setRefreshing(false)
    }
  }, [activeTypes])

  const handleLoadMore = useCallback(async () => {
    if (!nextCursor || loadingMore) return
    setLoadingMore(true)
    try {
      const resp = await listActivity({
        limit: 50,
        cursor: nextCursor,
        ...(activeTypes.length > 0 ? { types: activeTypes } : {}),
      })
      setEvents((prev) => [...prev, ...resp.events])
      setNextCursor(resp.next_cursor)
    } catch {
      // Silently fail on load-more — user can retry by clicking again
    } finally {
      setLoadingMore(false)
    }
  }, [nextCursor, loadingMore, activeTypes])

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
          <Button
            variant="secondary"
            size="sm"
            onClick={handleRefresh}
            disabled={refreshing || loading}
            isLoading={refreshing}
            title="Refresh"
            leadingIcon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0 3.181 3.183a8.25 8.25 0 0 0 13.803-3.7M4.031 9.865a8.25 8.25 0 0 1 13.803-3.7l3.181 3.182m0-4.991v4.99" />
              </svg>
            }
          >
            Refresh
          </Button>
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
          <Button variant="ghost" size="xs" onClick={handleClearFilters}>
            Clear
          </Button>
        </div>
      )}

      <div className="mx-auto w-full max-w-3xl px-4 py-6">
        {/* Catch-up banner — shown when user has been away for >24h */}
        {showCatchUp && (
          <CatchUpBanner data={catchUp} onDismiss={handleDismissBanner} />
        )}

        {/* Error state */}
        {error && (
          <div
            role="alert"
            className="mb-4 rounded-lg border border-[var(--color-severity-high-border)] bg-[var(--color-severity-high-subtle)] px-4 py-3 text-sm text-[var(--color-severity-high)]"
          >
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
