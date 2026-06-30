"use client"

import { useEffect, useRef, useState } from "react"
import { cn } from "@/lib/shared/utils"

const APPROX_COST_PER_1K_TOKENS = 0.01

interface UsageMeterProps {
  used: number
  budget: number
}

function statusFor(pct: number): {
  label: string
  barClass: string
  pillClass: string
} {
  if (pct >= 95) {
    return {
      label: "Near cap",
      barClass: "bg-[var(--color-severity-critical)]",
      pillClass:
        "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)]",
    }
  }
  if (pct >= 75) {
    return {
      label: "Approaching cap",
      barClass: "bg-[var(--color-severity-medium)]",
      pillClass:
        "bg-[var(--color-severity-medium-subtle)] text-[var(--color-severity-medium)]",
    }
  }
  return {
    label: "Healthy",
    barClass: "bg-[var(--color-accent)]",
    pillClass: "",
  }
}

export function UsageMeter({ used, budget }: UsageMeterProps) {
  const pct = budget > 0 ? Math.min(100, (used / budget) * 100) : 0
  const status = statusFor(pct)
  const cost = (used / 1000) * APPROX_COST_PER_1K_TOKENS

  const prev = useRef(pct)
  const [animatedPct, setAnimatedPct] = useState(pct)
  useEffect(() => {
    if (prev.current !== pct) {
      setAnimatedPct(pct)
      prev.current = pct
    }
  }, [pct])

  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
            Daily usage
          </span>
          {pct >= 75 && (
            <span
              className={cn(
                "inline-flex items-center rounded px-1.5 py-0.5 text-2xs font-semibold uppercase tracking-[0.14em]",
                status.pillClass,
              )}
            >
              {status.label}
            </span>
          )}
        </div>
        <span className="tabular-nums text-2xs font-semibold text-[var(--color-text-secondary)]">
          {used.toLocaleString()} / {budget.toLocaleString()}
        </span>
      </div>
      <div
        role="progressbar"
        aria-valuenow={used}
        aria-valuemin={0}
        aria-valuemax={budget}
        aria-label="Daily Argus token usage"
        className="h-2 overflow-hidden rounded-full border border-[var(--color-border)] bg-[var(--color-surface)]"
      >
        <div
          className={cn(
            "h-full transition-[width] duration-300 ease-out",
            status.barClass,
          )}
          style={{ width: `${animatedPct}%` }}
        />
      </div>
      <p className="mt-1 text-xs text-[var(--color-text-secondary)] tabular-nums">
        ~${cost.toFixed(2)} today
      </p>
    </div>
  )
}
