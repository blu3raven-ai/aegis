"use client"

import { useEffect, useState } from "react"
import { cn } from "@/lib/shared/utils"
import { Button } from "@/components/ui/Button"
import { LinkButton } from "@/components/ui/LinkButton"

const DISMISS_KEY = "aegis.dismiss.enable-verification-banner"
const RESHOW_AFTER_MS = 30 * 24 * 60 * 60 * 1000 // 30 days

type Dismissal = { dismissedAt: number }

function readDismissal(): Dismissal | null {
  if (typeof window === "undefined") return null
  const raw = window.localStorage.getItem(DISMISS_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw) as Dismissal
  } catch {
    return null
  }
}

interface EnableVerificationBannerProps {
  verificationEnabled: boolean
}

/**
 * Soft prompt above the findings list inviting an admin to set up LLM
 * verification. Hidden when the org already has it enabled, or the user has
 * dismissed it within the last 30 days.
 */
export function EnableVerificationBanner({ verificationEnabled }: EnableVerificationBannerProps) {
  const [collapsed, setCollapsed] = useState(false)
  const [shouldShow, setShouldShow] = useState(false)

  useEffect(() => {
    if (verificationEnabled) return
    const d = readDismissal()
    if (d && Date.now() - d.dismissedAt < RESHOW_AFTER_MS) {
      setShouldShow(false)
      return
    }
    setShouldShow(true)
  }, [verificationEnabled])

  function dismiss() {
    setCollapsed(true)
    window.localStorage.setItem(
      DISMISS_KEY,
      JSON.stringify({ dismissedAt: Date.now() } satisfies Dismissal),
    )
    window.setTimeout(() => setShouldShow(false), 250)
  }

  if (verificationEnabled || !shouldShow) return null

  return (
    <div
      role="region"
      aria-label="LLM verification setup"
      className={cn(
        "overflow-hidden transition-all duration-200 ease-out",
        collapsed ? "max-h-0 opacity-0" : "max-h-40 opacity-100",
      )}
    >
      <div className="rounded-md border border-[var(--color-border)] border-l-2 border-l-[var(--color-accent)] bg-[var(--color-bg-section)] px-4 py-3 flex items-start gap-3">
        <svg
          aria-hidden="true"
          viewBox="0 0 24 24"
          fill="currentColor"
          className="mt-0.5 h-4 w-4 shrink-0 text-[var(--color-accent)]"
        >
          <path d="M12 3l1.6 4.4L18 9l-4.4 1.6L12 15l-1.6-4.4L6 9l4.4-1.6L12 3z" />
          <path d="M18.5 14l.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8.8-2.2z" />
        </svg>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-[var(--color-text-primary)]">
            Enable LLM verification to filter false positives
          </p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)] leading-relaxed">
            Your model runs an AI verification pass on SAST, IaC, and dependency findings
            to mark them as confirmed, needs verify, possible, or ruled out —
            typically reducing noise by 40–60%.
          </p>
          <div className="mt-2 flex items-center gap-3">
            <LinkButton
              href="/settings#llm"
              variant="primary"
              size="sm"
              trailingIcon={<span aria-hidden="true">→</span>}
            >
              Enable verification
            </LinkButton>
            <Button variant="ghost" size="sm" onClick={dismiss}>
              Dismiss
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
