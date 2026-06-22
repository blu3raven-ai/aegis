"use client"

import { useEffect, useState } from "react"
import { getPostureTrend, type TrendPoint } from "@/lib/client/posture-api"

const NEUTRAL = "text-[var(--color-text-primary)]"
const OK = "text-[var(--color-state-fixed)]"
const CRITICAL = "text-[var(--color-severity-critical)]"

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
    <div className="flex flex-col rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-3 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
      <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
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
  const deltaLabel = points.length < 2
    ? "1 day of history"
    : `${arrow} ${Math.abs(delta)} vs ${points.length} days ago`

  return (
    <>
      <p className={`mt-2 text-2xl font-semibold leading-none tabular-nums ${valueClass}`}>
        {current}
      </p>
      <Sparkline points={points} />
      <p className="mt-1 text-sm text-[var(--color-text-secondary)]">{deltaLabel}</p>
    </>
  )
}

function Sparkline({ points }: { points: TrendPoint[] }) {
  if (points.length < 2) return null

  const w = 160
  const h = 28
  const totals = points.map((p) => p.total)
  const min = Math.min(...totals)
  const max = Math.max(...totals)
  const range = max - min || 1
  const stepX = points.length > 1 ? w / (points.length - 1) : 0
  const coords = points.map((p, i) => {
    const x = i * stepX
    const y = h - ((p.total - min) / range) * h
    return `${x.toFixed(2)},${y.toFixed(2)}`
  }).join(" ")

  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="mt-2 h-7 w-full" preserveAspectRatio="none" aria-hidden="true">
      <polyline points={coords} fill="none" stroke="currentColor" strokeWidth="1.5" className="text-[var(--color-accent)]" />
    </svg>
  )
}
