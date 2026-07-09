"use client"

import { useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/Button"

interface DismissPopoverProps {
  reasons: readonly string[]
  onDismiss: (reason: string) => void
  isLoading: boolean
  triggerLabel?: string
  /** Which way the menu opens — "top" for bottom-anchored bars, "bottom" for top action rows. */
  placement?: "top" | "bottom"
}

export function DismissPopover({
  reasons,
  onDismiss,
  isLoading,
  triggerLabel = "Dismiss finding",
  placement = "top",
}: DismissPopoverProps) {
  const [open, setOpen] = useState(false)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const rootRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (open) {
      const first = menuRef.current?.querySelector<HTMLElement>('[role="menuitem"]')
      first?.focus()
    }
  }, [open])

  // Close on an outside click. Ref the OUTER container (not the menu) so that
  // re-clicking the trigger to toggle-close isn't misread as an outside click.
  useEffect(() => {
    if (!open) return
    const onMouseDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener("mousedown", onMouseDown)
    return () => document.removeEventListener("mousedown", onMouseDown)
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
    <div ref={rootRef} className="relative">
      <Button
        ref={triggerRef}
        variant="secondary"
        size="sm"
        onClick={() => setOpen(!open)}
        disabled={isLoading}
        aria-haspopup="menu"
        aria-expanded={open}
      >
        {triggerLabel}
      </Button>
      {open && (
        <div
          ref={menuRef}
          role="menu"
          onKeyDown={handleKeyDown}
          className={`absolute right-0 z-50 min-w-[16rem] max-w-[min(20rem,calc(100vw-2rem))] rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-2 shadow-lg ${
            placement === "bottom" ? "top-full mt-1" : "bottom-full mb-1"
          }`}
        >
          <p className="px-2 py-1 text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
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
