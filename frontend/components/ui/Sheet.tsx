"use client"

import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from "react"
import { cn } from "@/lib/shared/utils"

type SheetSize = "sm" | "md" | "lg" | "xl"

interface DismissGuard {
  /** When true, dismissing the sheet (backdrop click, Esc, X) prompts to confirm. */
  isDirty: boolean
  /** Override the confirm-prompt copy. */
  message?: string
}

interface SheetProps {
  open: boolean
  onClose: () => void
  title: string
  description?: string
  size?: SheetSize
  dismissGuard?: DismissGuard
  /** Body content (scrolls if it overflows). */
  children?: ReactNode
  /** Optional sticky footer for action buttons. */
  footer?: ReactNode
}

const sizeClasses: Record<SheetSize, string> = {
  sm: "max-w-md",
  md: "max-w-lg",
  lg: "max-w-2xl",
  xl: "max-w-4xl",
}

const ENTER_MS = 280
const EXIT_MS = 200

// Right-side slide-over drawer. Used for create/edit flows where the user
// benefits from keeping the underlying list/table visible — Linear / Stripe /
// Notion all follow this pattern for non-blocking forms. Dialogs stay reserved
// for confirmation prompts.
export function Sheet({
  open,
  onClose,
  title,
  description,
  size = "md",
  dismissGuard,
  children,
  footer,
}: SheetProps) {
  const titleId = useId()
  const sheetRef = useRef<HTMLDivElement>(null)
  const previouslyFocusedRef = useRef<HTMLElement | null>(null)
  const [mounted, setMounted] = useState(open)
  const [animatingIn, setAnimatingIn] = useState(false)

  // Coordinate mount/unmount with the slide animation so closing doesn't
  // snap. Mount on open, run an animation frame to flip the in-class, then
  // unmount EXIT_MS after open flips back to false.
  useEffect(() => {
    if (open) {
      setMounted(true)
      const raf = requestAnimationFrame(() => setAnimatingIn(true))
      return () => cancelAnimationFrame(raf)
    }
    setAnimatingIn(false)
    const t = window.setTimeout(() => setMounted(false), EXIT_MS)
    return () => window.clearTimeout(t)
  }, [open])

  const handleClose = useCallback(() => {
    if (dismissGuard?.isDirty) {
      const ok = window.confirm(
        dismissGuard.message ?? "You have unsaved changes. Discard and close?",
      )
      if (!ok) return
    }
    onClose()
  }, [dismissGuard?.isDirty, dismissGuard?.message, onClose])

  // Esc to close.
  useEffect(() => {
    if (!open) return
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") handleClose()
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [open, handleClose])

  // Lock body scroll while the sheet is open. The app shell uses
  // overflow:hidden on html/body and scrolls inside <main>; lock that main
  // too so background list/table doesn't scroll under the drawer.
  useEffect(() => {
    if (!mounted) return
    const main = document.querySelector<HTMLElement>("main[data-app-scroll]")
    const prev = main?.style.overflow ?? ""
    if (main) main.style.overflow = "hidden"
    return () => {
      if (main) main.style.overflow = prev
    }
  }, [mounted])

  // Move focus into the sheet on open, restore on close.
  useEffect(() => {
    if (open) {
      previouslyFocusedRef.current = document.activeElement as HTMLElement | null
      sheetRef.current?.focus()
    } else if (previouslyFocusedRef.current) {
      previouslyFocusedRef.current.focus()
      previouslyFocusedRef.current = null
    }
  }, [open])

  if (!mounted) return null

  return (
    <div className="fixed inset-0 z-[100]" role="presentation">
      <div
        aria-hidden="true"
        onClick={handleClose}
        className={cn(
          "fixed inset-0 bg-[var(--color-overlay-strong)] transition-opacity",
          animatingIn ? "opacity-100" : "opacity-0",
        )}
        style={{ transitionDuration: `${animatingIn ? ENTER_MS : EXIT_MS}ms` }}
      />
      <div
        ref={sheetRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className={cn(
          "fixed inset-y-0 right-0 flex w-full flex-col border-l border-[var(--color-border)] bg-[var(--color-surface)] shadow-2xl outline-none transition-transform ease-out",
          sizeClasses[size],
          animatingIn ? "translate-x-0" : "translate-x-full",
        )}
        style={{ transitionDuration: `${animatingIn ? ENTER_MS : EXIT_MS}ms` }}
      >
        <header className="flex items-start justify-between gap-4 border-b border-[var(--color-border)] px-6 py-4">
          <div className="min-w-0 flex-1">
            <h2
              id={titleId}
              className="text-base font-semibold text-[var(--color-text-primary)]"
            >
              {title}
            </h2>
            {description && (
              <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
                {description}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={handleClose}
            aria-label="Close"
            className="-mr-1 inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
          >
            <svg
              className="h-4 w-4"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
              aria-hidden="true"
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />
            </svg>
          </button>
        </header>

        <div className="flex-1 overflow-y-auto px-6 py-5">{children}</div>

        {footer && (
          <footer className="border-t border-[var(--color-border)] bg-[var(--color-bg-section)] px-6 py-3">
            {footer}
          </footer>
        )}
      </div>
    </div>
  )
}

export type { SheetProps, SheetSize }
