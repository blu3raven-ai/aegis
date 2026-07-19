"use client"

import { useEffect, useMemo, useState } from "react"

import {
  getLlmUsage,
  APPROX_COST_PER_1K_TOKENS,
  type LlmUsage,
} from "@/lib/client/llm-settings-api"
import { KpiCard } from "@/components/shared/KpiCard"
import { CostChart } from "@/components/shared/settings/llm/CostChart"
import { UsageMeter } from "@/components/shared/settings/llm/UsageMeter"
import { SegmentedControl } from "@/components/ui/SegmentedControl"
import { Card } from "@/components/ui/Card"
import { Skeleton } from "@/components/ui/Skeleton"
import { Button } from "@/components/ui/Button"

const RANGES = [
  { id: "7", label: "7d" },
  { id: "30", label: "30d" },
  { id: "90", label: "90d" },
] as const
type RangeId = (typeof RANGES)[number]["id"]

/** Compact token count for KPI values (12.3k / 1.2M). */
function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`
  return n.toLocaleString()
}

/**
 * LLM verification usage — token spend and scan volume from the daily usage
 * ledger (`/api/v1/settings/llm/usage`). Self-contained: it only fetches when
 * mounted, so the Insights page doesn't pay for it unless the tab is opened.
 * The ledger is populated by verified scans, so an org that hasn't run LLM
 * verification sees an honest empty state rather than fabricated numbers.
 */
export function PostureUsageTab() {
  const [days, setDays] = useState<RangeId>("30")
  const [usage, setUsage] = useState<LlmUsage | null>(null)
  const [state, setState] = useState<"loading" | "ok" | "error">("loading")
  const [refreshKey, setRefreshKey] = useState(0)

  // The previous window stays on screen while a new range loads so switching
  // ranges doesn't flash the whole tab back to skeletons. Setting loading here
  // also clears any prior error when a retry re-runs this effect.
  useEffect(() => {
    let active = true
    setState("loading")
    getLlmUsage(Number(days))
      .then((u) => {
        if (!active) return
        setUsage(u)
        setState("ok")
      })
      .catch(() => {
        if (active) setState("error")
      })
    return () => {
      active = false
    }
  }, [days, refreshKey])

  // Live refresh: verification usage is written when a scan finishes ingesting,
  // so poll in the background (and on tab focus) to surface new spend without a
  // manual reload. Silent by design — it updates the numbers in place and never
  // flips the tab back to skeletons. No immediate fetch here; the effect above
  // owns the initial load, so mount doesn't double-fetch.
  useEffect(() => {
    let active = true
    const refresh = () => {
      if (typeof document !== "undefined" && document.hidden) return
      getLlmUsage(Number(days))
        .then((u) => {
          if (active) {
            setUsage(u)
            setState("ok")
          }
        })
        .catch(() => {
          // Keep the last good window on a transient failure.
        })
    }
    const id = window.setInterval(refresh, 15000)
    window.addEventListener("focus", refresh)
    return () => {
      active = false
      window.clearInterval(id)
      window.removeEventListener("focus", refresh)
    }
  }, [days])

  const retry = () => setRefreshKey((k) => k + 1)

  const totals = useMemo(() => {
    const rows = usage?.days ?? []
    const tokensIn = rows.reduce((s, d) => s + (d.tokens_in ?? 0), 0)
    const tokensOut = rows.reduce((s, d) => s + (d.tokens_out ?? 0), 0)
    const scans = rows.reduce((s, d) => s + (d.scans ?? 0), 0)
    const cost = ((tokensIn + tokensOut) / 1000) * APPROX_COST_PER_1K_TOKENS
    return { tokensIn, tokensOut, scans, cost }
  }, [usage])

  const rangeControl = (
    <SegmentedControl
      options={RANGES}
      value={days}
      onChange={setDays}
      ariaLabel="Usage time range"
    />
  )

  // Only a failed initial load (no data yet) blanks the tab. A failure while
  // switching ranges keeps the last-good window on screen (see inline banner).
  if (state === "error" && usage === null) {
    return (
      <div className="space-y-5 px-6 py-5">
        <Card padding="none" className="rounded-md px-6 py-12 text-center">
          <p className="text-sm font-medium text-[var(--color-text-primary)]">
            Could not load usage data
          </p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            The backend may be unavailable. Check that the server is running and try again.
          </p>
          <div className="mt-4 inline-flex">
            <Button variant="secondary" size="sm" onClick={retry}>
              Retry
            </Button>
          </div>
        </Card>
      </div>
    )
  }

  if (usage === null) {
    return (
      <div className="space-y-5 px-6 py-5">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-24 rounded-xl" />
          ))}
        </div>
        <Skeleton className="h-56 rounded-2xl" />
      </div>
    )
  }

  return (
    <div className="space-y-5 px-6 py-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
            LLM verification usage
          </h2>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            Token spend and scan volume from LLM-based finding verification.
          </p>
        </div>
        {rangeControl}
      </div>

      {state === "error" && (
        <div className="flex items-center justify-between gap-3 rounded-lg border border-[var(--color-danger)]/30 bg-[var(--color-danger)]/5 px-4 py-2.5">
          <p className="text-xs text-[var(--color-text-secondary)]">
            Couldn&apos;t refresh usage data. Showing the last loaded window.
          </p>
          <Button variant="secondary" size="xs" onClick={retry}>
            Retry
          </Button>
        </div>
      )}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard
          label="Tokens in"
          value={formatTokens(totals.tokensIn)}
          note={`Last ${days} days`}
          valueClass="text-[var(--color-text-primary)]"
        />
        <KpiCard
          label="Tokens out"
          value={formatTokens(totals.tokensOut)}
          note={`Last ${days} days`}
          valueClass="text-[var(--color-text-primary)]"
        />
        <KpiCard
          label="Scans"
          value={totals.scans.toLocaleString()}
          note="Verified in window"
          valueClass="text-[var(--color-text-primary)]"
        />
        <KpiCard
          label="Est. cost"
          value={`~$${totals.cost.toFixed(2)}`}
          note="Approximate, display only"
          valueClass="text-[var(--color-text-primary)]"
        />
      </div>

      <Card padding="md">
        <UsageMeter used={usage.today_used} budget={usage.today_budget} />
        {usage.today_budget === 0 && (
          <p className="mt-2 text-xs text-[var(--color-text-tertiary)]">
            No daily token budget is configured. Set one under Settings → LLM to track quota.
          </p>
        )}
      </Card>

      <Card padding="md">
        <CostChart days={usage.days} />
      </Card>
    </div>
  )
}
