"use client"

import { useEffect, useState } from "react"
import { ArgusTag } from "./ArgusTag"

interface IntelLiveBannerProps {
  /** Message pushed from Argus intel — show banner when non-null */
  message: string | null
  onDismiss: () => void
}

/**
 * Animated banner that slides in above the filter row when Argus pushes
 * new intel. Disappears after dismiss or 8 s auto-timeout.
 *
 * Uses --color-state-dismissed (purple) tokens — no new design tokens.
 */
export function IntelLiveBanner({ message, onDismiss }: IntelLiveBannerProps) {
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    if (message) {
      setVisible(true)
      const timer = setTimeout(() => {
        setVisible(false)
        onDismiss()
      }, 8000)
      return () => clearTimeout(timer)
    } else {
      setVisible(false)
    }
  }, [message, onDismiss])

  if (!visible || !message) return null

  return (
    <div
      role="status"
      aria-live="polite"
      className="flex items-center gap-3 border-b border-[var(--color-state-dismissed-border,rgba(168,85,247,0.30))] bg-[var(--color-state-dismissed-subtle,rgba(168,85,247,0.05))] px-5 py-2.5 text-[12px]"
    >
      <span
        className="inline-block h-2 w-2 shrink-0 animate-[scan-pulse_2s_ease-in-out_infinite] rounded-full"
        style={{ background: "var(--color-state-dismissed)" }}
        aria-hidden="true"
      />
      <ArgusTag />
      <span className="text-[var(--color-text-primary)]">{message}</span>
      <button
        type="button"
        onClick={() => {
          setVisible(false)
          onDismiss()
        }}
        className="ml-auto text-[var(--color-text-tertiary)] hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
        aria-label="Dismiss intel banner"
      >
        <svg className="h-3.5 w-3.5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
          <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z" />
        </svg>
      </button>
    </div>
  )
}
