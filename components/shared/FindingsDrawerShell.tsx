"use client"

import { useEffect } from "react"

export function FindingsDrawerShell({
  open,
  onClose,
  children,
}: {
  open: boolean
  onClose: () => void
  children: React.ReactNode
}) {
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose()
    }
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [onClose])

  return (
    <aside
      className={`fixed right-0 top-0 z-40 h-full w-full overflow-y-auto border-l border-[var(--color-border)] bg-[var(--color-surface)] shadow-[0_28px_80px_rgba(15,23,42,0.18)] transition-transform duration-200 ease-out xl:w-[60vw] ${open ? "translate-x-0" : "translate-x-full"}`}
    >
      {children}
    </aside>
  )
}
