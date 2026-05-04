"use client"

import { useEffect, useState, useCallback, useRef } from "react"
import { useRouter } from "next/navigation"
import { useSSE } from "@/components/providers/SSEProvider"
import { PageHeader } from "@/components/layout/PageHeader"
import { timeAgo } from "@/lib/shared/time-ago"
import {
  fetchNotifications,
  markNotificationRead,
  deleteNotification,
  type Notification,
} from "@/lib/client/notifications-api"
import { refreshNotificationCount } from "@/lib/client/use-notifications"
import type { NotificationNewEvent } from "@/lib/shared/sse-types"

// ─── Helpers ──────────────────────────────────────────────────────────────────

type DateGroup = "Today" | "Yesterday" | "Earlier"

function dateGroup(iso: string): DateGroup {
  const d = new Date(iso)
  const now = new Date()
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate())
  const yesterday = new Date(today.getTime() - 86_400_000)
  const notifDay = new Date(d.getFullYear(), d.getMonth(), d.getDate())
  if (notifDay.getTime() === today.getTime()) return "Today"
  if (notifDay.getTime() === yesterday.getTime()) return "Yesterday"
  return "Earlier"
}

function groupNotifications(
  items: Notification[]
): { label: DateGroup; items: Notification[] }[] {
  const groups: Record<DateGroup, Notification[]> = {
    Today: [],
    Yesterday: [],
    Earlier: [],
  }
  for (const n of items) {
    groups[dateGroup(n.createdAt)].push(n)
  }
  const order: DateGroup[] = ["Today", "Yesterday", "Earlier"]
  return order.filter((k) => groups[k].length > 0).map((k) => ({ label: k, items: groups[k] }))
}

const SEVERITY_CONFIG: Record<string, { dot: string; label: string }> = {
  info: { dot: "bg-[var(--color-accent)]", label: "Info" },
  warning: { dot: "bg-amber-500", label: "Warning" },
  error: { dot: "bg-[var(--color-severity-critical)]", label: "Critical" },
}

// ─── Skeleton ────────────────────────────────────────────────────────────────

function SkeletonRow() {
  return (
    <div className="flex items-center gap-4 px-5 py-4">
      <div className="h-2.5 w-2.5 shrink-0 rounded-full bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
      <div className="flex flex-1 flex-col gap-1.5">
        <div className="h-3.5 w-48 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
        <div className="h-3 w-72 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
      </div>
      <div className="h-3 w-12 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
    </div>
  )
}

// ─── Undo Toast ──────────────────────────────────────────────────────────────

function UndoToast({ message, onUndo, onDismiss }: { message: string; onUndo: () => void; onDismiss: () => void }) {
  useEffect(() => {
    const timer = setTimeout(onDismiss, 5000)
    return () => clearTimeout(timer)
  }, [onDismiss])

  return (
    <div className="fixed bottom-6 left-1/2 z-50 -translate-x-1/2 flex items-center gap-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3 shadow-lg">
      <p className="text-[0.8125rem] text-[var(--color-text-primary)]">{message}</p>
      <button
        type="button"
        onClick={onUndo}
        className="shrink-0 rounded-md px-2.5 py-1 text-xs font-semibold text-[var(--color-accent)] transition-colors hover:bg-[var(--color-accent)]/10"
      >
        Undo
      </button>
    </div>
  )
}

// ─── Bell Icon ───────────────────────────────────────────────────────────────

function BellIcon() {
  return (
    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--color-accent)]/10">
      <svg
        className="h-4 w-4 text-[var(--color-accent)]"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={2}
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M14.857 17.082a23.848 23.848 0 0 0 5.454-1.31A8.967 8.967 0 0 1 18 9.75V9A6 6 0 0 0 6 9v.75a8.967 8.967 0 0 1-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 0 1-5.714 0m5.714 0a3 3 0 1 1-5.714 0" />
      </svg>
    </div>
  )
}

// ─── Component ────────────────────────────────────────────────────────────────

export function NotificationsContent() {
  const router = useRouter()
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState<"all" | "unread">("all")
  const [focusedId, setFocusedId] = useState<string | null>(null)
  const [undoState, setUndoState] = useState<{ notification: Notification; timer: ReturnType<typeof setTimeout> } | null>(null)
  const [newAvailable, setNewAvailable] = useState(false)

  const notificationsRef = useRef(notifications)
  notificationsRef.current = notifications

  const load = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const result = await fetchNotifications({ unreadOnly: filter === "unread", limit: 100 })
      setNotifications(result.notifications)
      setNewAvailable(false)
    } catch {
      setError("Failed to load notifications. Check your connection and try again.")
    } finally {
      setIsLoading(false)
    }
  }, [filter])

  useEffect(() => {
    void load()
  }, [load])

  // SSE: show banner when new notifications arrive
  useSSE("notification.new", (_data: NotificationNewEvent) => {
    setNewAvailable(true)
  })

  const unreadCount = notifications.filter((n) => !n.readAt).length

  const handleMarkAllRead = async () => {
    const previous = [...notifications]
    setNotifications((prev) => prev.map((n) => ({ ...n, readAt: n.readAt ?? new Date().toISOString() })))
    try {
      await markNotificationRead()
      refreshNotificationCount()
    } catch {
      setNotifications(previous)
      setError("Failed to mark notifications as read.")
    }
  }

  const handleDelete = async (e: React.MouseEvent | React.KeyboardEvent, id: string) => {
    e.stopPropagation()
    const target = notifications.find((n) => n.id === id)
    if (!target) return

    // Clear any existing undo
    if (undoState) {
      clearTimeout(undoState.timer)
      setUndoState(null)
    }

    // Optimistic removal
    setNotifications((prev) => prev.filter((n) => n.id !== id))

    // Set up undo with 5s window
    const timer = setTimeout(async () => {
      setUndoState(null)
      try {
        await deleteNotification(id)
      } catch {
        // Restore on failure
        setNotifications((prev) => {
          const exists = prev.some((n) => n.id === id)
          if (exists) return prev
          return [...prev, target].sort(
            (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
          )
        })
        setError("Failed to delete notification.")
      }
    }, 5000)

    setUndoState({ notification: target, timer })
  }

  const handleUndo = () => {
    if (!undoState) return
    clearTimeout(undoState.timer)
    const restored = undoState.notification
    setUndoState(null)
    setNotifications((prev) =>
      [...prev, restored].sort(
        (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
      )
    )
  }

  const handleClick = async (n: Notification) => {
    if (!n.readAt) {
      setNotifications((prev) =>
        prev.map((item) => (item.id === n.id ? { ...item, readAt: new Date().toISOString() } : item))
      )
      try {
        await markNotificationRead(n.id)
        refreshNotificationCount()
      } catch {
        // Non-critical — don't block navigation
      }
    }
    if (n.link) {
      router.push(n.link)
    }
  }

  const grouped = groupNotifications(notifications)

  return (
    <>
      <PageHeader
        icon={<BellIcon />}
        title="Notifications"
        description="Scan completions, new findings, and system alerts"
        controls={
          <button
            type="button"
            onClick={handleMarkAllRead}
            disabled={unreadCount === 0 || isLoading}
            className="shrink-0 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)] disabled:pointer-events-none disabled:opacity-40"
          >
            Mark all as read
          </button>
        }
      />

      <div className="max-w-7xl mx-auto w-full px-6 py-8 space-y-6">
        {/* Filter toggle */}
        <div className="flex items-center gap-4">
          <div className="flex gap-1 rounded-2xl bg-[var(--color-surface)] p-1 border border-[var(--color-border)] w-fit">
            {(["all", "unread"] as const).map((f) => (
              <button
                key={f}
                type="button"
                onClick={() => setFilter(f)}
                className={`rounded-xl px-3.5 py-1.5 text-xs font-medium capitalize transition-colors ${
                  filter === f
                    ? "bg-[var(--color-surface-raised)] text-[var(--color-text-primary)] shadow-sm"
                    : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        {/* New notifications banner */}
        {newAvailable && !isLoading && (
          <button
            type="button"
            onClick={() => void load()}
            className="flex w-full items-center justify-center gap-2 rounded-2xl border border-[var(--color-accent)]/20 bg-[var(--color-accent)]/5 px-4 py-2.5 text-[0.8125rem] font-medium text-[var(--color-accent)] transition-colors hover:bg-[var(--color-accent)]/10"
          >
            <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 5v14M5 12l7-7 7 7" />
            </svg>
            New notifications available
          </button>
        )}

        {/* Error banner */}
        {error && (
          <div className="flex items-center gap-3 rounded-2xl border border-[var(--color-severity-critical)]/20 bg-[var(--color-severity-critical)]/5 px-5 py-3">
            <svg className="h-4 w-4 shrink-0 text-[var(--color-severity-critical)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
            <p className="flex-1 text-[0.8125rem] text-[var(--color-severity-critical)]">{error}</p>
            <button
              type="button"
              onClick={() => { setError(null); void load() }}
              className="shrink-0 rounded-md px-2.5 py-1 text-xs font-semibold text-[var(--color-severity-critical)] transition-colors hover:bg-[var(--color-severity-critical)]/10"
            >
              Retry
            </button>
          </div>
        )}

        {/* Loading */}
        {isLoading ? (
          <div className="divide-y divide-[var(--color-border)] overflow-hidden rounded-[28px] border border-[var(--color-border)] bg-[var(--color-surface)]">
            <SkeletonRow />
            <SkeletonRow />
            <SkeletonRow />
            <SkeletonRow />
          </div>
        ) : !error && notifications.length === 0 ? (
          /* Empty state */
          <div className="rounded-[28px] border-2 border-dashed border-[var(--color-border)] px-6 py-16 text-center">
            <svg
              className="mx-auto h-10 w-10 text-[var(--color-text-secondary)]"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={1.5}
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M14.857 17.082a23.848 23.848 0 0 0 5.454-1.31A8.967 8.967 0 0 1 18 9.75V9A6 6 0 0 0 6 9v.75a8.967 8.967 0 0 1-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 0 1-5.714 0m5.714 0a3 3 0 1 1-5.714 0" />
            </svg>
            <p className="mt-3 text-sm font-medium text-[var(--color-text-primary)]">
              No notifications yet
            </p>
            <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
              {filter === "unread"
                ? "You're all caught up!"
                : "Notifications will appear here as scans complete and findings are detected."}
            </p>
          </div>
        ) : !error && (
          /* Grouped list */
          <div className="space-y-6">
            {grouped.map((group) => (
              <div key={group.label}>
                <p className="mb-3 text-[0.6875rem] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
                  {group.label}
                </p>
                <div className="divide-y divide-[var(--color-border)] overflow-hidden rounded-[28px] border border-[var(--color-border)] bg-[var(--color-surface)]">
                  {group.items.map((n) => {
                    const sev = SEVERITY_CONFIG[n.severity] ?? SEVERITY_CONFIG.info
                    const isActive = focusedId === n.id
                    return (
                      <div
                        key={n.id}
                        role="button"
                        tabIndex={0}
                        onClick={() => handleClick(n)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault()
                            handleClick(n)
                          }
                        }}
                        onMouseEnter={() => setFocusedId(n.id)}
                        onMouseLeave={() => setFocusedId(null)}
                        onFocus={() => setFocusedId(n.id)}
                        onBlur={() => setFocusedId(null)}
                        className={`group flex items-center gap-4 px-5 py-4 transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-inset ${
                          n.link ? "hover:bg-[var(--color-surface-raised)]" : ""
                        } ${!n.readAt ? "bg-[var(--color-accent)]/[0.03]" : ""}`}
                      >
                        {/* Severity indicator with tooltip */}
                        <div className="relative shrink-0" title={sev.label}>
                          <div className={`h-2.5 w-2.5 rounded-full ${sev.dot}`} />
                          <span className="sr-only">{sev.label}</span>
                        </div>

                        {/* Content */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <p className="text-[0.8125rem] font-medium text-[var(--color-text-primary)] truncate">
                              {n.title}
                            </p>
                            {!n.readAt && (
                              <div className="h-2 w-2 shrink-0 rounded-full bg-[var(--color-accent)]" aria-label="Unread" />
                            )}
                          </div>
                          <p className="mt-0.5 text-xs text-[var(--color-text-secondary)] line-clamp-2">
                            {n.message}
                          </p>
                        </div>

                        {/* Right side: severity label, timestamp, delete */}
                        <div className="flex items-center gap-3 shrink-0">
                          <span className="hidden sm:inline text-[0.6875rem] font-medium uppercase tracking-wider text-[var(--color-text-secondary)]">
                            {sev.label}
                          </span>
                          <span className="text-[0.6875rem] text-[var(--color-text-secondary)] whitespace-nowrap tabular-nums">
                            {timeAgo(n.createdAt)}
                          </span>

                          <button
                            type="button"
                            aria-label="Delete notification"
                            onClick={(e) => handleDelete(e, n.id)}
                            onKeyDown={(e) => {
                              if (e.key === "Enter" || e.key === " ") {
                                e.preventDefault()
                                handleDelete(e, n.id)
                              }
                            }}
                            className={`rounded-md p-1.5 text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] ${
                              isActive ? "opacity-100" : "opacity-0 group-focus-within:opacity-100"
                            }`}
                            tabIndex={0}
                          >
                            <svg
                              className="h-3.5 w-3.5"
                              viewBox="0 0 24 24"
                              fill="none"
                              stroke="currentColor"
                              strokeWidth={2}
                              strokeLinecap="round"
                              strokeLinejoin="round"
                            >
                              <line x1="18" y1="6" x2="6" y2="18" />
                              <line x1="6" y1="6" x2="18" y2="18" />
                            </svg>
                          </button>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Undo toast */}
      {undoState && (
        <UndoToast
          message="Notification deleted"
          onUndo={handleUndo}
          onDismiss={() => setUndoState(null)}
        />
      )}
    </>
  )
}
