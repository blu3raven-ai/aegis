"use client"

import { useEffect, useRef } from "react"
import Link from "next/link"
import { NotificationsTabBody } from "@/components/layout/NotificationsTabBody"
import { useDialogA11y } from "@/lib/client/use-dialog-a11y"

interface NotificationDrawerProps {
  open: boolean
  onClose: () => void
}

export function NotificationDrawer({ open, onClose }: NotificationDrawerProps) {
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

  // Move focus into the drawer on open, trap Tab, and restore it to the trigger
  // on close. Escape/outside-click are already handled above.
  useDialogA11y(panelRef, onClose, open)

  if (!open) return null

  return (
    <>
      <div className="fixed inset-0 z-40 bg-[var(--color-overlay)]" aria-hidden="true" />

      <aside
        ref={panelRef}
        tabIndex={-1}
        role="dialog"
        aria-label="Notifications"
        className="fixed right-0 top-0 z-50 flex h-full w-full max-w-md flex-col border-l border-[var(--color-border)] bg-[var(--color-surface)] shadow-[var(--shadow-card)] focus:outline-none"
      >
        <div className="flex h-14 shrink-0 items-center justify-between gap-2 border-b border-[var(--color-border)] px-4">
          <h2 className="text-sm font-semibold text-[var(--color-text-primary)]">Notifications</h2>
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

        <div className="flex-1 overflow-y-auto">
          <NotificationsTabBody onNavigate={onClose} />
        </div>

        {/* The full event timeline lives on the Inbox History tab. */}
        <div className="shrink-0 border-t border-[var(--color-border)] px-4 py-3">
          <Link
            href="/inbox/history"
            onClick={onClose}
            className="flex items-center justify-center gap-1.5 rounded-lg px-4 py-2 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
          >
            View all
            <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M9 18l6-6-6-6" />
            </svg>
          </Link>
        </div>
      </aside>
    </>
  )
}
