"use client"

import { useEffect, useRef, useState } from "react"
import { ActivityTabBody } from "@/components/shared/activity/ActivityTabBody"
import { NotificationsTabBody } from "@/components/layout/NotificationsTabBody"

type DrawerTab = "notifications" | "activity"

interface NotificationDrawerProps {
  open: boolean
  onClose: () => void
}

export function NotificationDrawer({ open, onClose }: NotificationDrawerProps) {
  const [tab, setTab] = useState<DrawerTab>("notifications")
  const panelRef = useRef<HTMLDivElement>(null)

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

  if (!open) return null

  return (
    <>
      <div className="fixed inset-0 z-40 bg-[var(--color-overlay)]" aria-hidden="true" />

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
            <NotificationsTabBody onNavigate={onClose} />
          ) : (
            <ActivityTabBody onNavigate={onClose} />
          )}
        </div>
      </aside>
    </>
  )
}

function DrawerTabButton({
  id,
  active,
  onClick,
  children,
}: {
  id: string
  active: boolean
  onClick: () => void
  children: React.ReactNode
}) {
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
