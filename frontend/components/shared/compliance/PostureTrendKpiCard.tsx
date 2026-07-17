"use client"

import { useEffect, useState } from "react"
import { getPostureTrend, type TrendPoint } from "@/lib/client/posture-api"
import { Sparkline } from "@/components/shared/charts/Sparkline"

const NEUTRAL = "text-[var(--color-text-primary)]"
const OK = "text-[var(--color-state-fixed-text)]"
const CRITICAL = "text-[var(--color-severity-critical-text)]"

interface Props {
  days?: number
}

export function PostureTrendKpiCard({ days = 30 }: Props) {
  const [points, setPoints] = useState<TrendPoint[] | null>(null)
  const [errored, setErrored] = useState(false)

  useEffect(() => {
    let cancelled = false
    getPostureTrend(days)
      .then((r) => { if (!cancelled) setPoints(r.points) })
      .catch(() => { if (!cancelled) setErrored(true) })
    return () => { cancelled = true }
  }, [days])

  return (
    <div className="flex flex-col rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-3 shadow-[var(--shadow-card)]">
      <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        Posture trend ({days}d)
      </p>
      <Body points={points} errored={errored} />
    </div>
  )
}

function Body({ points, errored }: { points: TrendPoint[] | null; errored: boolean }) {
  if (errored) {
    return (
      <>
        <p className={`mt-2 text-2xl font-semibold leading-none tabular-nums ${NEUTRAL}`}>—</p>
        <p className="mt-2 text-sm text-[var(--color-text-secondary)]">Unavailable</p>
      </>
    )
  }
  if (points === null) {
    return (
      <>
        <p className={`mt-2 text-2xl font-semibold leading-none tabular-nums ${NEUTRAL}`}>…</p>
        <p className="mt-2 text-sm text-[var(--color-text-secondary)]">Loading…</p>
      </>
    )
  }
  if (points.length === 0) {
    return (
      <>
        <p className={`mt-2 text-2xl font-semibold leading-none tabular-nums ${NEUTRAL}`}>—</p>
        <p className="mt-2 text-sm text-[var(--color-text-secondary)]">No history yet</p>
      </>
    )
  }

  const current = points[points.length - 1].total
  const first = points[0].total
  const delta = current - first
  const valueClass = delta <= 0 ? OK : CRITICAL
  const arrow = points.length < 2 ? "" : delta < 0 ? "▼" : delta > 0 ? "▲" : "·"
  // The series is sparse (one row per snapshot date), so points.length counts
  // days-with-data, not the baseline's age — derive the real span from the dates.
  const spanDays = Math.round(
    (Date.parse(points[points.length - 1].date) - Date.parse(points[0].date)) / 86_400_000,
  )
  const deltaLabel = points.length < 2
    ? "1 day of history"
    : `${arrow} ${Math.abs(delta)} vs ${spanDays} ${spanDays === 1 ? "day" : "days"} ago`

  return (
    <>
      <p className={`mt-2 text-2xl font-semibold leading-none tabular-nums ${valueClass}`}>
        {current}
      </p>
      <Sparkline
        values={points.map((p) => p.total)}
        stroke="var(--color-accent)"
        className="mt-2 h-7 w-full"
      />
      <p className="mt-1 text-sm text-[var(--color-text-secondary)]">{deltaLabel}</p>
    </>
  )
}
