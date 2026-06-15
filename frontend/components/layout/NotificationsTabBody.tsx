"use client"

import { useCallback, useEffect, useState } from "react"
import Link from "next/link"
import {
  fetchNotifications,
  markNotificationRead,
  type Notification,
} from "@/lib/client/notifications-api"
import { refreshNotificationCount } from "@/lib/client/use-notifications"
import { timeAgo } from "@/lib/shared/time-ago"
import { Button } from "@/components/ui/Button"

const PAGE_SIZE = 20

interface NotificationsTabBodyProps {
  onNavigate: () => void
}

export function NotificationsTabBody({ onNavigate }: NotificationsTabBodyProps) {
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)

  const loadFirstPage = useCallback(async () => {
    setLoading(true)
    try {
      const resp = await fetchNotifications({ limit: PAGE_SIZE, offset: 0 })
      setNotifications(resp.notifications)
      setTotal(resp.total)
      setOffset(resp.notifications.length)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadFirstPage()
  }, [loadFirstPage])

  const handleLoadMore = useCallback(async () => {
    if (loadingMore) return
    setLoadingMore(true)
    try {
      const resp = await fetchNotifications({ limit: PAGE_SIZE, offset })
      setNotifications((prev) => [...prev, ...resp.notifications])
      setOffset((prev) => prev + resp.notifications.length)
      setTotal(resp.total)
    } finally {
      setLoadingMore(false)
    }
  }, [offset, loadingMore])

  const handleMarkRead = useCallback(async (id: string) => {
    await markNotificationRead(id)
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, readAt: new Date().toISOString() } : n)),
    )
    refreshNotificationCount()
  }, [])

  const handleMarkAllRead = useCallback(async () => {
    await markNotificationRead()
    setNotifications((prev) =>
      prev.map((n) => ({ ...n, readAt: n.readAt ?? new Date().toISOString() })),
    )
    refreshNotificationCount()
  }, [])

  const unreadCount = notifications.filter((n) => !n.readAt).length
  const hasMore = notifications.length < total

  if (loading && notifications.length === 0) {
    return (
      <div className="flex flex-col gap-2 p-3" aria-label="Loading notifications">
        {[1, 2, 3].map((n) => (
          <div
            key={n}
            className="h-14 animate-pulse rounded-lg bg-[var(--color-surface-raised)]"
            aria-hidden="true"
          />
        ))}
      </div>
    )
  }

  if (notifications.length === 0) {
    return (
      <div className="flex h-full flex-col items-center justify-center px-6 py-12 text-center">
        <p className="text-sm font-medium text-[var(--color-text-primary)]">No notifications.</p>
        <p className="mt-1 text-xs text-[var(--color-text-secondary)]">No notifications right now.</p>
      </div>
    )
  }

  return (
    <div>
      {unreadCount > 0 && (
        <div className="flex items-center justify-between border-b border-[var(--color-border)] px-3 py-2 text-xs">
          <span className="text-[var(--color-text-secondary)]">{unreadCount} unread</span>
          <Button
            variant="ghost"
            size="xs"
            onClick={handleMarkAllRead}
            className="text-[var(--color-accent)] hover:bg-[var(--color-accent)]/10 hover:text-[var(--color-accent)]"
          >
            Mark all read
          </Button>
        </div>
      )}

      <ul className="divide-y divide-[var(--color-border)]">
        {notifications.map((n) => {
          const unread = !n.readAt
          const body = (
            <div className="flex items-start gap-3 px-3 py-3">
              <span
                aria-hidden="true"
                className={`mt-1 h-1.5 w-1.5 shrink-0 rounded-full ${unread ? "bg-[var(--color-accent)]" : "bg-transparent"}`}
              />
              <div className="min-w-0 flex-1">
                <p
                  className={`truncate text-sm ${unread ? "font-semibold text-[var(--color-text-primary)]" : "text-[var(--color-text-secondary)]"}`}
                >
                  {n.title}
                </p>
                <p className="mt-0.5 line-clamp-2 text-xs text-[var(--color-text-secondary)]">
                  {n.message}
                </p>
                <p className="mt-1 text-[11px] text-[var(--color-text-tertiary)]">
                  {timeAgo(n.createdAt)}
                </p>
              </div>
            </div>
          )
          if (n.link) {
            return (
              <li key={n.id}>
                <Link
                  href={n.link}
                  onClick={() => {
                    if (unread) handleMarkRead(n.id)
                    onNavigate()
                  }}
                  className="block transition-colors hover:bg-[var(--color-surface-raised)]"
                >
                  {body}
                </Link>
              </li>
            )
          }
          return (
            <li key={n.id}>
              <button
                type="button"
                onClick={() => unread && handleMarkRead(n.id)}
                className="block w-full text-left transition-colors hover:bg-[var(--color-surface-raised)]"
              >
                {body}
              </button>
            </li>
          )
        })}
      </ul>

      {hasMore && (
        <div className="flex justify-center px-3 py-3">
          <Button
            variant="secondary"
            size="sm"
            onClick={handleLoadMore}
            disabled={loadingMore}
            isLoading={loadingMore}
          >
            {loadingMore ? "Loading…" : "Load older →"}
          </Button>
        </div>
      )}
    </div>
  )
}
