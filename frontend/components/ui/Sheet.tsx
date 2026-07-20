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
  /**
   * How the panel presents itself. `drawer` (default) is a right-side
   * slide-over that keeps the underlying list visible. `modal` centres the
   * same panel as a dialog — use it for focused settings/workspace edit flows
   * where the form is the sole task. Everything else (header, footer, focus
   * trap, dismiss guard, scroll lock) is identical across both.
   */
  variant?: "drawer" | "modal"
  dismissGuard?: DismissGuard
  /**
   * Replaces the default title/description/close row. The custom header owns
   * its own close affordance and the body becomes a bare flex column so the
   * caller controls padding and scrolling.
   */
  header?: ReactNode
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

// Stack of currently-open sheet ids so that, when sheets nest (e.g. the code
// "Expand" sheet over the finding detail sheet), only the topmost one responds
// to Esc — otherwise a single press would dismiss every open sheet.
const openSheetIds: string[] = []

/** Number of sheets currently open — lets hosts scope global key handlers to
 *  only fire when their sheet is the top (or only) layer. */
export function openSheetCount(): number {
  return openSheetIds.length
}

// Presents a titled form panel either as a right-side slide-over (default) or a
// centred modal (`variant="modal"`). The drawer keeps the underlying list
// visible for non-blocking edits; the modal focuses the user on a single task.
export function Sheet({
  open,
  onClose,
  title,
  description,
  size = "md",
  variant = "drawer",
  dismissGuard,
  header,
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

  // Latest close handler via ref so the stack/key effect can register once on
  // open without re-running every render (callers pass inline onClose), which
  // would otherwise churn the stack order and make Esc close the wrong sheet.
  const handleCloseRef = useRef(handleClose)
  useEffect(() => { handleCloseRef.current = handleClose }, [handleClose])

  // Register on the open-sheet stack and own Esc + Tab focus-trapping, but only
  // while this sheet is the topmost one. Registered once per open so the stack
  // reflects true open order.
  useEffect(() => {
    if (!open) return
    openSheetIds.push(titleId)
    const isTopmost = () => openSheetIds[openSheetIds.length - 1] === titleId
    function onKey(e: KeyboardEvent) {
      if (!isTopmost()) return
      if (e.key === "Escape") {
        handleCloseRef.current()
        return
      }
      if (e.key !== "Tab") return
      const root = sheetRef.current
      if (!root) return
      const tabbables = Array.from(
        root.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((el) => el.offsetParent !== null)
      const active = document.activeElement as HTMLElement | null
      if (tabbables.length === 0) {
        e.preventDefault()
        root.focus()
        return
      }
      const first = tabbables[0]
      const last = tabbables[tabbables.length - 1]
      if (!root.contains(active)) {
        e.preventDefault()
        first.focus()
      } else if (e.shiftKey && (active === first || active === root)) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && active === last) {
        e.preventDefault()
        first.focus()
      }
    }
    window.addEventListener("keydown", onKey)
    return () => {
      window.removeEventListener("keydown", onKey)
      const i = openSheetIds.indexOf(titleId)
      if (i >= 0) openSheetIds.splice(i, 1)
    }
  }, [open, titleId])

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

  // Move focus into the sheet on open, restore on close. If the element that
  // had focus was removed while the sheet was open (e.g. the finding row was
  // dismissed), fall back to the main content region instead of dropping focus
  // to <body> and losing the user's place.
  useEffect(() => {
    if (open) {
      previouslyFocusedRef.current = document.activeElement as HTMLElement | null
      sheetRef.current?.focus()
    } else if (previouslyFocusedRef.current) {
      const prev = previouslyFocusedRef.current
      previouslyFocusedRef.current = null
      if (prev.isConnected) {
        prev.focus()
      } else {
        const main = document.querySelector<HTMLElement>("main[data-app-scroll]")
        if (main) {
          main.setAttribute("tabindex", "-1")
          main.focus()
        }
      }
    }
  }, [open])

  if (!mounted) return null

  const isModal = variant === "modal"

  return (
    <div
      className={cn("fixed inset-0 z-[100]", isModal && "flex items-center justify-center p-4")}
      role="presentation"
    >
      <div
        aria-hidden="true"
        onClick={handleClose}        className={cn(
          "fixed inset-0 bg-[var(--color-overlay-strong)] transition-opacity",
          animatingIn ? "opacity-100" : "opacity-0",
          isModal && "cursor-pointer hover:bg-[var(--color-overlay)]",
        )}
        style={{ transitionDuration: `${animatingIn ? ENTER_MS : EXIT_MS}ms` }}
      />
      <div
        ref={sheetRef}
        role="dialog"
        aria-modal="true"
        {...(header ? { "aria-label": title } : { "aria-labelledby": titleId })}
        tabIndex={-1}
        className={cn(
          "flex w-full flex-col bg-[var(--color-surface)] shadow-2xl outline-none ease-out",
          sizeClasses[size],
          isModal
            ? cn(
                "relative max-h-[85vh] overflow-hidden rounded-2xl border border-[var(--color-border)] transition-[opacity,transform]",
                animatingIn ? "scale-100 opacity-100" : "scale-95 opacity-0",
              )
            : cn(
                "fixed inset-y-0 right-0 border-l border-[var(--color-border)] transition-transform",
                animatingIn ? "translate-x-0" : "translate-x-full",
              ),
        )}
        style={{ transitionDuration: `${animatingIn ? ENTER_MS : EXIT_MS}ms` }}
      >
        {header ?? (
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
              onClick={handleClose}              aria-label="Close"
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
        )}

        {header ? (
          <div className="flex min-h-0 flex-1 flex-col">{children}</div>
        ) : (
          <div className="flex-1 overflow-y-auto px-6 py-5">{children}</div>
        )}

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
