"use client"

import { useMemo, useState } from "react"
import { APPROX_COST_PER_1K_TOKENS } from "@/lib/client/llm-settings-api"

interface DayUsage {
  date: string
  tokens_in: number
  tokens_out: number
}

interface CostChartProps {
  days: DayUsage[] | null
}

interface Bar {
  date: string
  fullDate: string
  tokens: number
}

function formatDate(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" })
}

function formatTick(v: number): string {
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`
  if (v >= 1_000) return `${(v / 1_000).toFixed(0)}k`
  return v.toString()
}

const HEIGHT = 160
const TOP_PAD = 6
const BOTTOM_PAD = 22
const LEFT_PAD = 36
const RIGHT_PAD = 4
const TICK_COUNT = 4

/**
 * Inline-SVG bar chart for daily token usage. No external chart dependency.
 * Renders a skeleton when `days` is null and an empty-state when the entire
 * window is zero.
 */
export function CostChart({ days }: CostChartProps) {
  const [hoverIdx, setHoverIdx] = useState<number | null>(null)

  const bars: Bar[] = useMemo(() => {
    if (!days) return []
    return days.map((d) => ({
      date: formatDate(d.date),
      fullDate: d.date,
      tokens: (d.tokens_in ?? 0) + (d.tokens_out ?? 0),
    }))
  }, [days])

  const maxTokens = useMemo(
    () => bars.reduce((m, b) => Math.max(m, b.tokens), 0),
    [bars],
  )
  const totalTokens = useMemo(
    () => bars.reduce((sum, b) => sum + b.tokens, 0),
    [bars],
  )

  if (days === null) {
    return (
      <div>
        <h3 className="mb-2 text-base font-semibold">Token usage</h3>
        <div
          style={{ height: HEIGHT }}
          className="motion-safe:animate-pulse rounded border border-[var(--color-border)] bg-[var(--color-surface)]"
        />
      </div>
    )
  }

  if (totalTokens === 0) {
    return (
      <div>
        <h3 className="mb-2 text-base font-semibold">Token usage</h3>
        <div
          style={{ height: HEIGHT }}
          className="flex items-center justify-center rounded border border-dashed border-[var(--color-border)] text-xs italic text-[var(--color-text-secondary)]"
        >
          No usage yet. Your next scan will show up here.
        </div>
      </div>
    )
  }

  const width = 600
  const chartWidth = width - LEFT_PAD - RIGHT_PAD
  const chartHeight = HEIGHT - TOP_PAD - BOTTOM_PAD
  const slot = chartWidth / Math.max(1, bars.length)
  const barWidth = Math.max(2, Math.floor(slot * 0.7))
  const xTickEvery = Math.max(1, Math.floor(bars.length / 7))

  const ticks: number[] = []
  for (let i = 0; i <= TICK_COUNT; i++) {
    ticks.push(Math.round((maxTokens * i) / TICK_COUNT))
  }

  const hoverBar = hoverIdx != null ? bars[hoverIdx] : null
  const hoverCost = hoverBar
    ? (hoverBar.tokens / 1000) * APPROX_COST_PER_1K_TOKENS
    : 0

  return (
    <div>
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-base font-semibold">Token usage</h3>
        <span className="text-2xs font-mono font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
          Last {bars.length} days
        </span>
      </div>
      <div className="relative">
        <svg
          role="img"
          aria-label="Daily token usage bar chart"
          viewBox={`0 0 ${width} ${HEIGHT}`}
          className="h-[160px] w-full"
        >
          {/* Horizontal gridlines */}
          {ticks.map((t, i) => {
            const y =
              TOP_PAD + chartHeight - (chartHeight * i) / TICK_COUNT
            return (
              <g key={i}>
                <line
                  x1={LEFT_PAD}
                  x2={LEFT_PAD + chartWidth}
                  y1={y}
                  y2={y}
                  stroke="var(--color-border)"
                  strokeDasharray="3 3"
                  strokeWidth={1}
                />
                <text
                  x={LEFT_PAD - 6}
                  y={y + 3}
                  textAnchor="end"
                  fontSize="10"
                  fill="var(--color-text-secondary)"
                >
                  {formatTick(t)}
                </text>
              </g>
            )
          })}

          {/* Bars */}
          {bars.map((b, i) => {
            const h =
              maxTokens > 0 ? (chartHeight * b.tokens) / maxTokens : 0
            const x = LEFT_PAD + i * slot + (slot - barWidth) / 2
            const y = TOP_PAD + chartHeight - h
            return (
              <rect
                key={b.fullDate}
                x={x}
                y={y}
                width={barWidth}
                height={Math.max(0, h)}
                rx={2}
                ry={2}
                fill="var(--color-accent)"
                onMouseEnter={() => setHoverIdx(i)}
                onMouseLeave={() =>
                  setHoverIdx((cur) => (cur === i ? null : cur))
                }
              >
                <title>
                  {formatDate(b.fullDate)}: {b.tokens.toLocaleString()} tokens
                </title>
              </rect>
            )
          })}

          {/* X-axis labels */}
          {bars.map((b, i) => {
            if (i % xTickEvery !== 0) return null
            const x = LEFT_PAD + i * slot + slot / 2
            return (
              <text
                key={`xt-${b.fullDate}`}
                x={x}
                y={HEIGHT - 6}
                textAnchor="middle"
                fontSize="10"
                fill="var(--color-text-secondary)"
              >
                {b.date}
              </text>
            )
          })}
        </svg>
        {hoverBar && (
          <div className="pointer-events-none absolute bottom-0 left-0 right-0 mx-auto w-fit rounded border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1 text-xs shadow-sm">
            <span className="font-semibold text-[var(--color-text-primary)]">
              {formatDate(hoverBar.fullDate)}
            </span>
            <span className="ml-2 tabular-nums text-[var(--color-text-secondary)]">
              {hoverBar.tokens.toLocaleString()} tokens · ~$
              {hoverCost.toFixed(3)}
            </span>
          </div>
        )}
      </div>
    </div>
  )
}
