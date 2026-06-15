"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { cn } from "@/lib/shared/utils"
import { Button } from "@/components/ui/Button"

const DISMISS_KEY = "aegis.dismiss.enable-llm-banner"
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

interface EnableLlmBannerProps {
  llmConfigured: boolean
}

/**
 * Soft prompt above the findings list inviting the admin to configure
 * LLM verification. Hidden when the org already has an LLM key set, or
 * when the user has dismissed it within the last 30 days.
 */
export function EnableLlmBanner({ llmConfigured }: EnableLlmBannerProps) {
  const [collapsed, setCollapsed] = useState(false)
  const [shouldShow, setShouldShow] = useState(false)

  useEffect(() => {
    if (llmConfigured) return
    const d = readDismissal()
    if (d && Date.now() - d.dismissedAt < RESHOW_AFTER_MS) {
      setShouldShow(false)
      return
    }
    setShouldShow(true)
  }, [llmConfigured])

  function dismiss() {
    setCollapsed(true)
    window.localStorage.setItem(
      DISMISS_KEY,
      JSON.stringify({ dismissedAt: Date.now() } satisfies Dismissal),
    )
    window.setTimeout(() => setShouldShow(false), 250)
  }

  if (llmConfigured || !shouldShow) return null

  return (
    <div
      role="region"
      aria-label="LLM verification setup"
      className={cn(
        "overflow-hidden transition-all duration-200 ease-out",
        collapsed ? "max-h-0 opacity-0" : "max-h-40 opacity-100",
      )}
    >
      <div className="rounded border border-[var(--color-border)] bg-[var(--color-bg-section)] px-4 py-3 flex items-start gap-3">
        <span aria-hidden className="text-base leading-none mt-0.5">
          ✨
        </span>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-[var(--color-text-primary)]">
            Enable LLM verification to filter false positives
          </p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)] leading-relaxed">
            Aegis can run an AI verification pass on SAST and secrets findings
            to mark them as confirmed, needs verify, possible, or ruled out —
            typically reducing noise by 40–60%. Bring your own API key.
          </p>
          <div className="mt-2 flex items-center gap-3">
            <Link href="/settings/llm" className="inline-flex">
              <Button variant="primary" size="sm" trailingIcon={<span aria-hidden="true">→</span>}>
                Configure
              </Button>
            </Link>
            <Button variant="ghost" size="sm" onClick={dismiss}>
              Dismiss
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
