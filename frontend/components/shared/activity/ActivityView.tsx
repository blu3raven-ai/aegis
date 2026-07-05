"use client"

import { useState, useCallback, useEffect } from "react"
import { ActivityFeed } from "./ActivityFeed"
import { CatchUpBanner } from "./CatchUpBanner"
import { HistorySidebar } from "./HistorySidebar"
import { eventTypeLabel } from "./event-labels"
import { listActivity } from "@/lib/client/activity-api"
import type { ActivityEvent } from "@/lib/client/activity-api"
import {
  deriveCatchUp,
  deriveDayStats,
  type CatchUpData,
  type DayStats,
} from "@/lib/shared/activity-derivations"

/**
 * Full activity feed body — shares the Inbox shell with the Triage tab: a left
 * filter rail (HistorySidebar) mirroring the triage queue rail, a slim top bar,
 * and a full-width feed. Renders no PageHeader of its own (the Inbox layout
 * owns the header + tab bar).
 */
export function ActivityView() {
  const [events, setEvents] = useState<ActivityEvent[]>([])
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Empty = "All activity". Single-select event-type filter driven by the rail.
  const [activeTypes, setActiveTypes] = useState<string[]>([])
  const [stats, setStats] = useState<DayStats | null>(null)
  const [catchUp, setCatchUp] = useState<CatchUpData | null>(null)
  const [catchUpDismissed, setCatchUpDismissed] = useState(false)

  // Fetch 24h stats (drives the rail counts) and conditionally the catch-up banner.
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
  const activeLabel =
    activeTypes.length === 0 ? "All activity" : activeTypes.map(eventTypeLabel).join(", ")

  return (
    <div className="flex h-full min-h-0">
      <HistorySidebar activeTypes={activeTypes} stats={stats} onSelect={setActiveTypes} />

      <div className="flex flex-1 min-w-0 flex-col overflow-hidden bg-[var(--color-bg)]">
        {/* Top bar — mirrors the Triage command bar height/padding */}
        <div className="flex items-center gap-3 border-b border-[var(--color-border-divider)] bg-[var(--color-surface)] px-5 py-2.5">
          <span className="text-sm font-medium text-[var(--color-text-primary)]">{activeLabel}</span>
          {stats && (
            <span className="text-xs tabular-nums text-[var(--color-text-tertiary)]">
              {stats.total.toLocaleString()} in last 24h
            </span>
          )}
        </div>

        {/* Feed — full-width, left-aligned to match the Triage list */}
        <div className="flex-1 overflow-auto px-5 py-4">
          {showCatchUp && (
            <CatchUpBanner data={catchUp} onDismiss={handleDismissBanner} />
          )}

          {error && (
            <div
              role="alert"
              className="mb-4 rounded-lg border border-[var(--color-severity-high-border)] bg-[var(--color-severity-high-subtle)] px-4 py-3 text-sm text-[var(--color-severity-high-text)]"
            >
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
        </div>
      </div>
    </div>
  )
}
