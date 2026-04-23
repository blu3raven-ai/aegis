"use client"

import Link from "next/link"
import { useNotificationCount } from "@/lib/client/use-notifications"

export function NotificationBell() {
  const { count } = useNotificationCount()
  const label = count > 0 ? `Notifications (${count} unread)` : "Notifications"
  const displayCount = count > 99 ? "99+" : String(count)

  return (
    <Link
      href="/notifications"
      aria-label={label}
      className="relative rounded-lg p-2 text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
    >
      <svg
        className="h-5 w-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M14.857 17.082a23.848 23.848 0 0 0 5.454-1.31A8.967 8.967 0 0 1 18 9.75V9A6 6 0 0 0 6 9v.75a8.967 8.967 0 0 1-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 0 1-5.714 0m5.714 0a3 3 0 1 1-5.714 0" />
      </svg>
      {count > 0 && (
        <span
          className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 px-1 text-[10px] font-bold text-white"
          aria-hidden="true"
        >
          {displayCount}
        </span>
      )}
    </Link>
  )
}
