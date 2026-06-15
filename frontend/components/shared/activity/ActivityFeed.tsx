"use client"

import { ActivityItem } from "./ActivityItem"
import { EmptyActivityState } from "./EmptyActivityState"
import type { ActivityEvent } from "@/lib/client/activity-api"
import { Button } from "@/components/ui/Button"

// ── Day grouping ──────────────────────────────────────────────────────────────

function dayLabel(isoString: string): string {
  try {
    const date = new Date(isoString)
    const now = new Date()
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate())
    const eventDay = new Date(date.getFullYear(), date.getMonth(), date.getDate())
    const diffMs = today.getTime() - eventDay.getTime()
    const diffDays = Math.round(diffMs / 86_400_000)

    if (diffDays === 0) return "Today"
    if (diffDays === 1) return "Yesterday"
    if (diffDays < 7) return `${diffDays} days ago`
    return date.toLocaleDateString(undefined, { month: "long", day: "numeric", year: "numeric" })
  } catch {
    return "Unknown"
  }
}

function groupByDay(events: ActivityEvent[]): Array<{ label: string; events: ActivityEvent[] }> {
  const groups: Map<string, ActivityEvent[]> = new Map()
  for (const evt of events) {
    const label = dayLabel(evt.occurred_at)
    const existing = groups.get(label)
    if (existing) {
      existing.push(evt)
    } else {
      groups.set(label, [evt])
    }
  }
  return Array.from(groups.entries()).map(([label, evts]) => ({ label, events: evts }))
}

// ── Component ─────────────────────────────────────────────────────────────────

interface ActivityFeedProps {
  events: ActivityEvent[]
  loading?: boolean
  hasMore?: boolean
  onLoadMore?: () => void
  loadingMore?: boolean
}

export function ActivityFeed({
  events,
  loading = false,
  hasMore = false,
  onLoadMore,
  loadingMore = false,
}: ActivityFeedProps) {
  if (loading) {
    return (
      <div className="flex flex-col gap-2 py-8" data-testid="activity-feed-loading">
        {Array.from({ length: 5 }).map((_, i) => (
          <div
            key={i}
            className="h-14 animate-pulse rounded-lg bg-[var(--color-surface-raised)]"
            aria-hidden="true"
          />
        ))}
      </div>
    )
  }

  if (!events.length) {
    return <EmptyActivityState />
  }

  const groups = groupByDay(events)

  return (
    <div className="flex flex-col gap-4" data-testid="activity-feed">
      {groups.map((group) => (
        <section key={group.label}>
          {/* Day header */}
          <div className="flex items-center gap-3 py-2">
            <span className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
              {group.label}
            </span>
            <div className="flex-1 h-px bg-[var(--color-border)]" aria-hidden="true" />
            <span className="text-2xs text-[var(--color-text-tertiary)] tabular-nums">
              {group.events.length} {group.events.length === 1 ? "event" : "events"}
            </span>
          </div>

          {/* Events */}
          <div className="flex flex-col divide-y divide-[var(--color-border)]">
            {group.events.map((evt) => (
              <ActivityItem key={evt.id} event={evt} />
            ))}
          </div>
        </section>
      ))}

      {/* Load more */}
      {hasMore && onLoadMore && (
        <div className="flex justify-center py-2">
          <Button
            variant="secondary"
            size="md"
            onClick={onLoadMore}
            disabled={loadingMore}
            isLoading={loadingMore}
          >
            {loadingMore ? "Loading…" : "Load older events →"}
          </Button>
        </div>
      )}
    </div>
  )
}
