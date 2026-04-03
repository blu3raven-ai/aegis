"use client"

import { useState, useRef, useCallback, type ReactNode } from "react"

interface TooltipProps {
  content: string
  children: ReactNode
}

const SHOW_DELAY = 300

/**
 * Lightweight tooltip that appears to the right of its trigger after a short
 * hover delay.  Only intended for the collapsed sidebar where nav icons lack
 * visible text labels.
 */
export function Tooltip({ content, children }: TooltipProps) {
  const [visible, setVisible] = useState(false)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const show = useCallback(() => {
    timerRef.current = setTimeout(() => setVisible(true), SHOW_DELAY)
  }, [])

  const hide = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current)
      timerRef.current = null
    }
    setVisible(false)
  }, [])

  return (
    <div className="relative" onMouseEnter={show} onMouseLeave={hide}>
      {children}
      {visible && (
        <div
          role="tooltip"
          className="absolute left-full ml-2 top-1/2 -translate-y-1/2 whitespace-nowrap bg-[var(--color-surface-raised)] text-[var(--color-text-primary)] text-xs rounded-md px-2 py-1 shadow-lg pointer-events-none z-50"
        >
          {content}
        </div>
      )}
    </div>
  )
}
