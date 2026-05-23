"use client"

import { useEffect, useRef, useState } from "react"

interface DismissPopoverProps {
  reasons: string[]
  onDismiss: (reason: string) => void
  isLoading: boolean
  triggerLabel?: string
}

export function DismissPopover({
  reasons,
  onDismiss,
  isLoading,
  triggerLabel = "Dismiss finding",
}: DismissPopoverProps) {
  const [open, setOpen] = useState(false)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (open) {
      const first = menuRef.current?.querySelector<HTMLElement>('[role="menuitem"]')
      first?.focus()
    }
  }, [open])

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape") {
      e.stopPropagation()
      setOpen(false)
      triggerRef.current?.focus()
      return
    }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault()
      const items = Array.from(
        menuRef.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? []
      )
      if (items.length === 0) return
      const currentIdx = items.indexOf(document.activeElement as HTMLElement)
      if (e.key === "ArrowDown") {
        items[(currentIdx + 1) % items.length]?.focus()
      } else {
        items[(currentIdx - 1 + items.length) % items.length]?.focus()
      }
    }
  }

  return (
    <div className="relative">
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setOpen(!open)}
        disabled={isLoading}
        aria-haspopup="menu"
        aria-expanded={open}
        className="rounded-lg border border-[var(--color-border)] px-3 py-2 text-xs font-semibold text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
      >
        {triggerLabel}
      </button>
      {open && (
        <div
          ref={menuRef}
          role="menu"
          onKeyDown={handleKeyDown}
          className="absolute bottom-full left-0 z-50 mb-1 min-w-[16rem] max-w-[calc(100%-1rem)] rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-2 shadow-lg"
        >
          <p className="px-2 py-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)]">
            Select reason
          </p>
          {reasons.map((reason) => (
            <button
              key={reason}
              type="button"
              role="menuitem"
              disabled={isLoading}
              onClick={() => {
                onDismiss(reason)
                setOpen(false)
              }}
              className="w-full rounded-lg px-2 py-1.5 text-left text-sm text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)] disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
            >
              {reason}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
