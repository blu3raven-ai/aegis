"use client"

import { useEffect, useRef } from "react"

const FOCUSABLE = 'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

export function FindingsDrawerShell({
  open,
  onClose,
  label,
  children,
}: {
  open: boolean
  onClose: () => void
  label: string
  children: React.ReactNode
}) {
  const shellRef = useRef<HTMLElement>(null)
  const triggerRef = useRef<Element | null>(null)

  useEffect(() => {
    if (open) {
      triggerRef.current = document.activeElement

      const timer = setTimeout(() => {
        const focusable = shellRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE)
        focusable?.[0]?.focus()
      }, 210)

      function handleKeyDown(e: KeyboardEvent) {
        if (e.key === "Escape") {
          onClose()
          return
        }
        if (e.key === "Tab") {
          const focusable = Array.from(
            shellRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? []
          )
          if (focusable.length === 0) return
          const first = focusable[0]
          const last = focusable[focusable.length - 1]
          if (e.shiftKey) {
            if (document.activeElement === first) {
              e.preventDefault()
              last.focus()
            }
          } else {
            if (document.activeElement === last) {
              e.preventDefault()
              first.focus()
            }
          }
        }
      }

      document.addEventListener("keydown", handleKeyDown)
      return () => {
        clearTimeout(timer)
        document.removeEventListener("keydown", handleKeyDown)
      }
    } else {
      if (triggerRef.current && document.contains(triggerRef.current)) {
        ;(triggerRef.current as HTMLElement).focus?.()
      }
    }
  }, [open, onClose])

  return (
    <aside
      ref={shellRef}
      role="dialog"
      aria-modal="true"
      aria-label={label}
      className={`fixed right-0 top-0 z-40 flex h-full w-full flex-col border-l border-[var(--color-border)] bg-[var(--color-surface)] shadow-[var(--shadow-nav)] transition-transform duration-200 ease-out xl:w-[60vw] ${open ? "translate-x-0" : "translate-x-full"}`}
    >
      {children}
    </aside>
  )
}
