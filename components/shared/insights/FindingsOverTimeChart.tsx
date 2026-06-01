"use client"

import { useMemo } from "react"
import type { TemporalSeriesPoint } from "@/lib/client/temporal-api"

const SEV_COLORS: Record<string, string> = {
  critical: "var(--color-severity-critical)",
  high:     "var(--color-severity-high)",
  medium:   "var(--color-severity-medium)",
  low:      "var(--color-severity-low)",
}

const SEV_ORDER = ["critical", "high", "medium", "low"] as const

function Skeleton() {
  return (
    <div className="flex flex-col gap-2 p-4 animate-pulse">
      <div className="h-3 w-32 rounded bg-[var(--color-surface-raised)]" />
      <div className="h-40 rounded-lg bg-[var(--color-surface-raised)]" />
    </div>
  )
}

function EmptyState() {
  return (
    <div className="flex min-h-[180px] items-center justify-center text-center px-6">
      <p className="text-[13px] text-[var(--color-text-secondary)]">
        No findings in this window. Try widening the time range.
      </p>
    </div>
  )
}

function ErrorState() {
  return (
    <div className="flex min-h-[180px] items-center justify-center text-center px-6">
      <p className="text-[13px] text-[var(--color-text-secondary)]">
        Couldn't load — temporal correlation may be disabled (
        <code className="font-mono text-[12px] text-[var(--color-text-primary)]">AEGIS_CORRELATION_ENABLED=true</code>
        {" "}required).
      </p>
    </div>
  )
}

// Aggregate multi-dimensional series into per-bucket per-severity totals
function aggregate(points: TemporalSeriesPoint[]) {
  const bucketMap = new Map<string, Record<string, number>>()
  for (const p of points) {
    const sev = p.dimension?.severity ?? "low"
    if (!bucketMap.has(p.bucket_start)) bucketMap.set(p.bucket_start, {})
    const row = bucketMap.get(p.bucket_start)!
    row[sev] = (row[sev] ?? 0) + p.value
  }
  // Sort chronologically
  return Array.from(bucketMap.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([bucket_start, counts]) => ({ bucket_start, counts }))
}

function formatBucket(iso: string) {
  const d = new Date(iso)
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" })
}

interface FindingsOverTimeChartProps {
  points: TemporalSeriesPoint[]
  loading: boolean
  error: boolean
}

export function FindingsOverTimeChart({ points, loading, error }: FindingsOverTimeChartProps) {
  const rows = useMemo(() => aggregate(points), [points])

  if (loading) return <Skeleton />
  if (error) return <ErrorState />
  if (rows.length === 0) return <EmptyState />

  const maxTotal = Math.max(
    1,
    ...rows.map((r) => SEV_ORDER.reduce((s, sev) => s + (r.counts[sev] ?? 0), 0)),
  )

  const chartH = 140
  const leftPad = 30
  const rightPad = 8
  const topPad = 8
  const bottomPad = 20
  const innerW = Math.max(1, rows.length * 36)
  const svgW = innerW + leftPad + rightPad
  const svgH = chartH + topPad + bottomPad

  // Build stacked bars
  const barWidth = Math.max(6, Math.min(24, (innerW / rows.length) * 0.6))
  const barGap = innerW / rows.length

  // Y-axis ticks
  const ticks = [0, 0.25, 0.5, 0.75, 1.0].map((f) => Math.round(maxTotal * f))

  return (
    <div className="overflow-x-auto">
      <svg
        viewBox={`0 0 ${svgW} ${svgH}`}
        style={{ minWidth: `${svgW}px`, width: "100%", height: `${svgH}px` }}
        aria-label="Findings introduced over time"
        role="img"
      >
        {/* Y-axis gridlines + labels */}
        {ticks.map((tick) => {
          const y = topPad + chartH - (tick / maxTotal) * chartH
          return (
            <g key={tick}>
              <line
                x1={leftPad}
                x2={leftPad + innerW + rightPad}
                y1={y}
                y2={y}
                stroke="var(--color-border)"
                strokeWidth={0.5}
              />
              <text
                x={leftPad - 4}
                y={y + 3.5}
                textAnchor="end"
                fontSize={8}
                fill="var(--color-text-tertiary)"
              >
                {tick}
              </text>
            </g>
          )
        })}

        {/* Stacked bars */}
        {rows.map((row, i) => {
          const x = leftPad + i * barGap + barGap / 2 - barWidth / 2
          let yOffset = 0
          return (
            <g key={row.bucket_start}>
              {SEV_ORDER.slice().reverse().map((sev) => {
                const val = row.counts[sev] ?? 0
                if (val === 0) return null
                const barH = (val / maxTotal) * chartH
                const y = topPad + chartH - yOffset - barH
                yOffset += barH
                return (
                  <rect
                    key={sev}
                    x={x}
                    y={y}
                    width={barWidth}
                    height={barH}
                    fill={SEV_COLORS[sev] ?? "var(--color-accent)"}
                    rx={1}
                    opacity={0.85}
                  >
                    <title>{`${sev}: ${val}`}</title>
                  </rect>
                )
              })}
              {/* X-axis label */}
              <text
                x={x + barWidth / 2}
                y={topPad + chartH + 12}
                textAnchor="middle"
                fontSize={7.5}
                fill="var(--color-text-tertiary)"
              >
                {formatBucket(row.bucket_start)}
              </text>
            </g>
          )
        })}
      </svg>

      {/* Legend */}
      <div className="mt-2 flex flex-wrap items-center gap-3 px-1">
        {SEV_ORDER.map((sev) => (
          <span key={sev} className="flex items-center gap-1.5 text-[11px] text-[var(--color-text-secondary)]">
            <span
              className="inline-block h-2 w-2 rounded-sm"
              style={{ background: SEV_COLORS[sev] }}
            />
            {sev.charAt(0).toUpperCase() + sev.slice(1)}
          </span>
        ))}
      </div>
    </div>
  )
}
