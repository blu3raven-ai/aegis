"use client"

import { useCallback, useEffect, useState } from "react"
import Link from "next/link"
import { ActivityFeed } from "./ActivityFeed"
import { ActivityFilterChip, eventTypeLabel } from "./ActivityFilterChip"
import { CatchUpBanner } from "./CatchUpBanner"
import { QuickFilterChips, FilterOverflow } from "./QuickFilterChips"
import { chipTypesFor } from "./event-labels"
import { listActivity, type ActivityEvent } from "@/lib/client/activity-api"
import {
  deriveCatchUp,
  deriveDayStats,
  type CatchUpData,
  type DayStats,
} from "@/lib/shared/activity-derivations"
import { Button } from "@/components/ui/Button"

interface ActivityTabBodyProps {
  onNavigate: () => void
}

export function ActivityTabBody({ onNavigate }: ActivityTabBodyProps) {
  const [events, setEvents] = useState<ActivityEvent[]>([])
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [activeTypes, setActiveTypes] = useState<string[]>(() => chipTypesFor("all"))
  const [activeChip, setActiveChip] = useState<string | null>("all")
  const [filterOpen, setFilterOpen] = useState(false)
  const [stats, setStats] = useState<DayStats | null>(null)
  const [catchUp, setCatchUp] = useState<CatchUpData | null>(null)
  const [catchUpDismissed, setCatchUpDismissed] = useState(false)

  // Stats + catch-up bootstrap, on mount only.
  useEffect(() => {
    const dayAgo = new Date(Date.now() - 24 * 3600_000).toISOString()
    listActivity({ since: dayAgo, limit: 200 })
      .then(({ events: e }) => setStats(deriveDayStats(e)))
      .catch(() => setStats(null))

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
      // localStorage unavailable — catch-up banner stays off this session
    }
  }, [])

  const load = useCallback(async (types: string[]) => {
    setLoading(true)
    setError(null)
    try {
      const params = {
        limit: 50,
        ...(types.length > 0 ? { types } : {}),
      }
      const resp = await listActivity(params)
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

  const handleLoadMore = useCallback(async () => {
    if (!nextCursor || loadingMore) return
    setLoadingMore(true)
    try {
      const params = {
        limit: 50,
        cursor: nextCursor,
        ...(activeTypes.length > 0 ? { types: activeTypes } : {}),
      }
      const resp = await listActivity(params)
      setEvents((prev) => [...prev, ...resp.events])
      setNextCursor(resp.next_cursor)
    } catch {
      // silently fail — user can retry
    } finally {
      setLoadingMore(false)
    }
  }, [nextCursor, loadingMore, activeTypes])

  const handleChipSelect = useCallback((chipId: string, types: string[]) => {
    setActiveChip(chipId)
    setActiveTypes(types)
  }, [])

  const handleTypeToggle = useCallback((type: string) => {
    setActiveChip(null)
    setActiveTypes((prev) =>
      prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type],
    )
  }, [])

  const handleClearFilters = useCallback(() => {
    setActiveTypes([])
    setActiveChip("all")
  }, [])

  const handleDismissBanner = useCallback(() => {
    setCatchUpDismissed(true)
    try {
      const today = new Date().toISOString().slice(0, 10)
      localStorage.setItem(`activity:catchup-dismissed:${today}`, "1")
    } catch {
      // session-only dismiss
    }
  }, [])

  const showCatchUp = catchUp !== null && !catchUpDismissed

  return (
    <div className="flex flex-col gap-3 p-3">
      {showCatchUp && (
        <CatchUpBanner data={catchUp} onDismiss={handleDismissBanner} />
      )}

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

      {activeChip === null && activeTypes.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          {activeTypes.map((type) => (
            <ActivityFilterChip
              key={type}
              label={eventTypeLabel(type)}
              active
              onToggle={() => handleTypeToggle(type)}
            />
          ))}
          <Button
            variant="link"
            size="xs"
            onClick={handleClearFilters}
            className="text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] underline"
          >
            Clear
          </Button>
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-[var(--color-severity-high)]/30 bg-[var(--color-severity-high)]/5 px-4 py-3 text-sm text-[var(--color-severity-high)]">
          {error}
        </div>
      )}

      <ActivityFeed
        events={events}
        loading={loading}
        hasMore={nextCursor !== null}
        onLoadMore={handleLoadMore}
        loadingMore={loadingMore}
      />

      <div className="mt-2 flex justify-center">
        <Link
          href="/activity"
          onClick={onNavigate}
          className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2 text-xs text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-text-primary)]"
        >
          View all activity
        </Link>
      </div>
    </div>
  )
}
