"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import Link from "next/link"
import { fetchNotifications, markNotificationRead, type Notification } from "@/lib/client/notifications-api"
import { refreshNotificationCount } from "@/lib/client/use-notifications"
import { listActivity, type ActivityEvent } from "@/lib/client/activity-api"
import { ActivityFeed } from "@/components/shared/activity/ActivityFeed"
import { timeAgo } from "@/lib/shared/time-ago"

type DrawerTab = "notifications" | "activity"

interface NotificationDrawerProps {
  open: boolean
  onClose: () => void
}

export function NotificationDrawer({ open, onClose }: NotificationDrawerProps) {
  const [tab, setTab] = useState<DrawerTab>("notifications")
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [notifLoading, setNotifLoading] = useState(false)
  const [activity, setActivity] = useState<ActivityEvent[]>([])
  const [activityLoading, setActivityLoading] = useState(false)
  const panelRef = useRef<HTMLDivElement>(null)

  // Load notifications on open
  const loadNotifications = useCallback(async () => {
    setNotifLoading(true)
    const resp = await fetchNotifications({ limit: 20 })
    setNotifications(resp.notifications)
    setNotifLoading(false)
  }, [])

  const loadActivity = useCallback(async () => {
    setActivityLoading(true)
    try {
      const resp = await listActivity({ limit: 30 })
      setActivity(resp.events)
    } catch {
      setActivity([])
    }
    setActivityLoading(false)
  }, [])

  useEffect(() => {
    if (!open) return
    if (tab === "notifications") void loadNotifications()
    if (tab === "activity") void loadActivity()
  }, [open, tab, loadNotifications, loadActivity])

  // Outside click → close
  useEffect(() => {
    if (!open) return
    function onDocClick(e: MouseEvent) {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        onClose()
      }
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose()
    }
    document.addEventListener("mousedown", onDocClick)
    document.addEventListener("keydown", onKey)
    return () => {
      document.removeEventListener("mousedown", onDocClick)
      document.removeEventListener("keydown", onKey)
    }
  }, [open, onClose])

  const handleMarkRead = useCallback(async (id: string) => {
    await markNotificationRead(id)
    setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, readAt: new Date().toISOString() } : n)))
    refreshNotificationCount()
  }, [])

  const handleMarkAllRead = useCallback(async () => {
    await markNotificationRead()
    setNotifications((prev) => prev.map((n) => ({ ...n, readAt: n.readAt ?? new Date().toISOString() })))
    refreshNotificationCount()
  }, [])

  if (!open) return null

  return (
    <>
      {/* Backdrop — semi-transparent, dismiss on click handled by panel ref */}
      <div className="fixed inset-0 z-40 bg-[var(--color-overlay)]" aria-hidden="true" />

      {/* Slide-in panel */}
      <aside
        ref={panelRef}
        role="dialog"
        aria-label="Notifications"
        className="fixed right-0 top-0 z-50 flex h-full w-full max-w-md flex-col border-l border-[var(--color-border)] bg-[var(--color-surface)] shadow-[var(--shadow-card)]"
      >
        <div className="flex h-14 shrink-0 items-center justify-between gap-2 border-b border-[var(--color-border)] px-4">
          <h2 className="text-sm font-semibold text-[var(--color-text-primary)]">Inbox</h2>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="rounded-lg p-2 text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
          >
            <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
              <path d="M6 18 18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Tabs */}
        <div role="tablist" aria-label="Inbox views" className="flex border-b border-[var(--color-border)] px-2">
          <DrawerTabButton id="notifications" active={tab === "notifications"} onClick={() => setTab("notifications")}>
            Notifications
          </DrawerTabButton>
          <DrawerTabButton id="activity" active={tab === "activity"} onClick={() => setTab("activity")}>
            Activity
          </DrawerTabButton>
        </div>

        <div className="flex-1 overflow-y-auto">
          {tab === "notifications" ? (
            <NotificationsList
              notifications={notifications}
              loading={notifLoading}
              onMarkRead={handleMarkRead}
              onMarkAllRead={handleMarkAllRead}
              onNavigate={onClose}
            />
          ) : (
            <div className="p-3">
              <ActivityFeed events={activity} loading={activityLoading} />
              <div className="mt-3 flex justify-center">
                <Link
                  href="/activity"
                  onClick={onClose}
                  className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2 text-xs text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-text-primary)]"
                >
                  View all activity
                </Link>
              </div>
            </div>
          )}
        </div>
      </aside>
    </>
  )
}

function DrawerTabButton({ id, active, onClick, children }: { id: string; active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      role="tab"
      type="button"
      aria-selected={active}
      data-tab-id={id}
      onClick={onClick}
      className={`-mb-px border-b-2 px-3 py-2.5 text-xs transition-colors ${
        active
          ? "border-[var(--color-accent)] font-semibold text-[var(--color-text-primary)]"
          : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
      }`}
    >
      {children}
    </button>
  )
}

function NotificationsList({
  notifications,
  loading,
  onMarkRead,
  onMarkAllRead,
  onNavigate,
}: {
  notifications: Notification[]
  loading: boolean
  onMarkRead: (id: string) => void
  onMarkAllRead: () => void
  onNavigate: () => void
}) {
  const unreadCount = notifications.filter((n) => !n.readAt).length

  if (loading && notifications.length === 0) {
    return (
      <div className="flex flex-col gap-2 p-3" aria-label="Loading notifications">
        {[1, 2, 3].map((n) => (
          <div key={n} className="h-14 animate-pulse rounded-lg bg-[var(--color-surface-raised)]" aria-hidden="true" />
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
          <button
            type="button"
            onClick={onMarkAllRead}
            className="rounded-md px-2 py-1 font-semibold text-[var(--color-accent)] transition-colors hover:bg-[var(--color-accent)]/10"
          >
            Mark all read
          </button>
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
                <p className={`truncate text-sm ${unread ? "font-semibold text-[var(--color-text-primary)]" : "text-[var(--color-text-secondary)]"}`}>
                  {n.title}
                </p>
                <p className="mt-0.5 line-clamp-2 text-xs text-[var(--color-text-secondary)]">{n.message}</p>
                <p className="mt-1 text-[11px] text-[var(--color-text-tertiary)]">{timeAgo(n.createdAt)}</p>
              </div>
            </div>
          )
          if (n.link) {
            return (
              <li key={n.id}>
                <Link
                  href={n.link}
                  onClick={() => {
                    if (unread) onMarkRead(n.id)
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
                onClick={() => unread && onMarkRead(n.id)}
                className="block w-full text-left transition-colors hover:bg-[var(--color-surface-raised)]"
              >
                {body}
              </button>
            </li>
          )
        })}
      </ul>
      <div className="border-t border-[var(--color-border)] p-3 text-center">
        <Link
          href="/notifications"
          onClick={onNavigate}
          className="text-xs font-semibold text-[var(--color-accent)] hover:underline"
        >
          View all notifications
        </Link>
      </div>
    </div>
  )
}
