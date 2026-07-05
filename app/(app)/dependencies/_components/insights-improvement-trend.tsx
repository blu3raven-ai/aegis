import type { GqlMonthlyTrendItem, GqlMTTRBySeverity } from "@/lib/shared/graphql/types"

// ── Chart constants ─────────────────────────────────────────────────────────────
const HEIGHT = 280
const PADDING = { top: 28, right: 28, bottom: 52, left: 48 }
const MIN_COL_WIDTH = 60

function yFor(value: number, max: number, plotHeight: number) {
  if (max <= 0) return PADDING.top + plotHeight
  return PADDING.top + plotHeight - (value / max) * plotHeight
}

function formatDelta(value: number) {
  if (value === 0) return "No change"
  return `${value > 0 ? "+" : ""}${value} vs prior month`
}

// ── BacklogAreaChart ────────────────────────────────────────────────────────────

function BacklogAreaChart({ trend }: { trend: { month: string; openAtEnd: number }[] }) {
  if (trend.length < 2) {
    return (
      <div className="flex min-h-40 items-center justify-center rounded-2xl border border-dashed border-[var(--color-border)] text-sm text-[var(--color-text-secondary)]">
        Not enough data to display.
      </div>
    )
  }

  const chartWidth = Math.max(560, (trend.length - 1) * MIN_COL_WIDTH + PADDING.left + PADDING.right)
  const plotWidth = chartWidth - PADDING.left - PADDING.right
  const plotHeight = HEIGHT - PADDING.top - PADDING.bottom
  const xStep = trend.length > 1 ? plotWidth / (trend.length - 1) : 0
  const maxY = Math.max(1, ...trend.map((e) => e.openAtEnd))
  const displayMaxY = Math.max(1, Math.ceil(maxY * 1.15))
  const ticks = Array.from({ length: 5 }, (_, i) => Math.round((displayMaxY / 4) * i))
  const baselineY = PADDING.top + plotHeight
  const latestEntry = trend.at(-1)
  const previousEntry = trend.at(-2)
  const latestValue = latestEntry?.openAtEnd ?? 0
  const latestDelta = latestValue - (previousEntry?.openAtEnd ?? latestValue)
  const latestDeltaTone =
    latestDelta < 0
      ? "border-[var(--color-state-fixed-border)] bg-[var(--color-state-fixed-subtle)] text-[var(--color-state-fixed)]"
      : latestDelta > 0
        ? "border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)]"
        : "border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-secondary)]"

  const points = trend.map((entry, index) => {
    const x = PADDING.left + (trend.length > 1 ? index * xStep : plotWidth / 2)
    const y = yFor(entry.openAtEnd, displayMaxY, plotHeight)
    return { x, y }
  })
  const latestPoint = points[points.length - 1]

  const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x} ${p.y}`).join(" ")
  const areaPath = [
    `M ${points[0].x} ${baselineY}`,
    ...points.map((p) => `L ${p.x} ${p.y}`),
    `L ${points[points.length - 1].x} ${baselineY}`,
    "Z",
  ].join(" ")

  return (
    <div className="space-y-4">
      {/* Info strip */}
      <div className="flex flex-wrap items-start justify-between gap-4 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
        <div className="min-w-0">
          <p className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">
            Latest backlog
          </p>
          <div className="mt-2 flex flex-wrap items-baseline gap-3">
            <span className="text-2xl font-semibold leading-none tabular-nums text-[var(--color-text-primary)]">
              {latestValue}
            </span>
            <span className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${latestDeltaTone}`}>
              {formatDelta(latestDelta)}
            </span>
          </div>
        </div>
        <div className="grid gap-2 sm:grid-cols-2">
          <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3">
            <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-[var(--color-text-secondary)]">
              Peak backlog
            </p>
            <p className="mt-2 text-2xl font-semibold text-[var(--color-text-primary)]">{maxY}</p>
          </div>
          <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3">
            <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-[var(--color-text-secondary)]">
              Direction
            </p>
            <p className={`mt-2 text-2xl font-semibold ${latestDelta < 0 ? "text-[var(--color-state-fixed)]" : latestDelta > 0 ? "text-[var(--color-severity-critical)]" : "text-[var(--color-text-primary)]"}`}>
              {latestDelta < 0 ? "Down" : latestDelta > 0 ? "Up" : "Flat"}
            </p>
          </div>
        </div>
      </div>

      {/* SVG area chart with legend */}
      <div className="flex gap-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
        <div className="min-w-0 flex-1 overflow-x-auto" style={{ direction: "rtl" }}>
          <svg
            width={chartWidth}
            height={HEIGHT}
            viewBox={`0 0 ${chartWidth} ${HEIGHT}`}
            className="block"
            style={{ direction: "ltr" }}
            role="img"
            aria-label="Open backlog over time"
          >
            <defs>
              <linearGradient id="dependencies-backlog-gradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#f97316" stopOpacity="0.26" />
                <stop offset="100%" stopColor="#f97316" stopOpacity="0.03" />
              </linearGradient>
              <radialGradient id="dependencies-backlog-glow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#fb923c" stopOpacity="0.35" />
                <stop offset="100%" stopColor="#fb923c" stopOpacity="0" />
              </radialGradient>
            </defs>

            <rect x="1" y="1" width={chartWidth - 2} height={HEIGHT - 2} rx="24" fill="var(--color-surface)" />

            {ticks.map((tick, i) => {
              const y = yFor(tick, displayMaxY, plotHeight)
              const isTopTick = i === ticks.length - 1
              return (
                <g key={i}>
                  <line
                    x1={PADDING.left}
                    y1={y}
                    x2={chartWidth - PADDING.right}
                    y2={y}
                    stroke="var(--color-border)"
                    strokeDasharray="4 4"
                    strokeOpacity={isTopTick ? 0.95 : 0.75}
                  />
                  <text
                    x={PADDING.left - 10}
                    y={y + 4}
                    textAnchor="end"
                    fontSize="10"
                    fontWeight={isTopTick ? 600 : 400}
                    fill={isTopTick ? "var(--color-text-primary)" : "var(--color-text-secondary)"}
                  >
                    {tick}
                  </text>
                </g>
              )
            })}

            <path d={areaPath} fill="url(#dependencies-backlog-gradient)" />
            <path
              d={linePath}
              fill="none"
              stroke="#f97316"
              strokeWidth="3"
              strokeLinejoin="round"
              strokeLinecap="round"
            />

            {points.map((p, index) => {
              const isLatest = index === points.length - 1
              return (
                <g key={trend[index].month}>
                  {isLatest ? (
                    <circle cx={p.x} cy={p.y} r="18" fill="url(#dependencies-backlog-glow)" />
                  ) : null}
                  <circle
                    cx={p.x}
                    cy={p.y}
                    r={isLatest ? 6 : 4}
                    fill={isLatest ? "#fb923c" : "#f97316"}
                  />
                  <text
                    x={p.x}
                    y={HEIGHT - 12}
                    textAnchor="middle"
                    fontSize="10"
                    fontWeight={isLatest ? 600 : 400}
                    fill={isLatest ? "var(--color-text-primary)" : "var(--color-text-secondary)"}
                  >
                    {trend[index].month}
                  </text>
                </g>
              )
            })}

            {latestPoint ? (
              <g>
                <line
                  x1={latestPoint.x}
                  y1={latestPoint.y}
                  x2={latestPoint.x}
                  y2={Math.max(PADDING.top, latestPoint.y - 34)}
                  stroke="#f97316"
                  strokeWidth="1.5"
                  strokeDasharray="3 3"
                  strokeOpacity="0.7"
                />
                <rect
                  x={Math.max(PADDING.left + 8, Math.min(chartWidth - 136, latestPoint.x - 104))}
                  y={Math.max(PADDING.top - 4, latestPoint.y - 72)}
                  width="132"
                  height="44"
                  rx="14"
                  fill="var(--color-surface-raised)"
                  stroke="var(--color-border)"
                />
                <text
                  x={Math.max(PADDING.left + 18, Math.min(chartWidth - 126, latestPoint.x - 94))}
                  y={Math.max(PADDING.top + 14, latestPoint.y - 47)}
                  fontSize="10"
                  fontWeight="600"
                  fill="var(--color-text-secondary)"
                >
                  Latest point
                </text>
                <text
                  x={Math.max(PADDING.left + 18, Math.min(chartWidth - 126, latestPoint.x - 94))}
                  y={Math.max(PADDING.top + 31, latestPoint.y - 28)}
                  fontSize="16"
                  fontWeight="700"
                  fill="var(--color-text-primary)"
                >
                  {latestValue}
                </text>
              </g>
            ) : null}
          </svg>
        </div>

        {/* Legend — pinned, never scrolls */}
        <div className="flex w-40 shrink-0 flex-col justify-center gap-3 border-l border-[var(--color-border)] pl-4">
          <div>
            <p className="text-xs font-semibold text-[var(--color-text-primary)]">Open backlog</p>
            <p className="mt-1 text-[11px] leading-relaxed text-[var(--color-text-secondary)]">
              Total open vulnerabilities over time. A downward slope indicates progress.
            </p>
          </div>
          <div className="rounded-xl border border-[var(--color-accent)]/30 bg-[var(--color-accent-subtle)] px-3 py-2">
            <p className="text-2xs font-semibold uppercase tracking-[0.18em] text-[var(--color-accent)]">Latest</p>
            <p className="mt-1 text-lg font-semibold text-[var(--color-accent)]">{latestValue}</p>
            <p className="text-2xs text-[var(--color-text-secondary)]">{latestEntry?.month ?? ""}</p>
          </div>
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-[#fb923c]" />
            <span className="text-[11px] text-[var(--color-text-secondary)]">Backlog size</span>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── MTTR severity colours ───────────────────────────────────────────────────────

const MTTR_COLOUR: Record<string, string> = {
  critical: "text-[var(--color-severity-critical)]",
  high:     "text-[var(--color-severity-high)]",
  medium:   "text-[var(--color-severity-medium)]",
  low:      "text-[var(--color-severity-low)]",
}

// ── InsightsImprovementTrend ────────────────────────────────────────────────────

export function InsightsImprovementTrend({
  monthlyTrend,
  mttrBySeverity,
}: {
  monthlyTrend: GqlMonthlyTrendItem[]
  mttrBySeverity: GqlMTTRBySeverity
}) {
  const trend = monthlyTrend
  const mttr  = mttrBySeverity

  const last6 = trend.slice(-6)
  const maxAbsDelta = Math.max(
    ...last6.map((m) => Math.abs(m.introduced - m.resolved)),
    1
  )

  return (
    <div className="space-y-6">
      {/* Section header */}
      <div className="border-t border-[var(--color-border)] pt-12">
        <h2 className="text-2xl font-bold text-[var(--color-text-primary)]">Backlog movement</h2>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          How quickly open issues are being resolved over time.
        </p>
      </div>

      {/* Backlog area chart */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
        <p className="mb-4 text-sm font-semibold text-[var(--color-text-primary)]">Open backlog over time</p>
        <BacklogAreaChart trend={trend} />
      </div>

      {/* Monthly net-change bars */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
        <p className="mb-4 text-sm font-semibold text-[var(--color-text-primary)]">
          Monthly net change (last 6 months)
        </p>
        <div className="space-y-4">
          {last6.length === 0 ? (
            <p className="text-sm text-[var(--color-text-secondary)]">Not enough data to display.</p>
          ) : (
            last6.map((m) => {
              const net = m.introduced - m.resolved
              const absNet = Math.abs(net)
              const widthPct = Math.round((absNet / maxAbsDelta) * 100)
              const isUp = net > 0
              const isFlat = net === 0
              const barClass = isFlat
                ? "bg-[var(--color-border)]"
                : isUp
                  ? "bg-[var(--color-severity-high)]"
                  : "bg-[var(--color-state-fixed)]"
              const label = isFlat
                ? "→ flat"
                : isUp
                  ? `▲ net +${net}`
                  : `▼ net −${absNet}`
              const labelClass = isFlat
                ? "text-[var(--color-text-secondary)]"
                : isUp
                  ? "text-[var(--color-severity-high)]"
                  : "text-[var(--color-state-fixed)]"

              return (
                <div key={m.month}>
                  <div className="flex items-center gap-3">
                    <span className="w-16 shrink-0 text-right text-xs text-[var(--color-text-secondary)]">
                      {m.month}
                    </span>
                    <div className="flex-1 overflow-hidden rounded-full bg-[var(--color-border)]" style={{ height: 32 }}>
                      <div
                        className={`flex h-full items-center rounded-full px-3 ${barClass}`}
                        style={{ width: `${Math.max(widthPct, absNet ? 8 : 100)}%` }}
                      >
                        <span className={`text-xs font-semibold ${isFlat ? "text-[var(--color-text-secondary)]" : "text-white"}`}>
                          {label}
                        </span>
                      </div>
                    </div>
                  </div>
                  <p className="mt-1 pl-[76px] text-xs text-[var(--color-text-secondary)]">
                    {m.introduced} introduced · {m.resolved} resolved
                  </p>
                </div>
              )
            })
          )}
        </div>
      </div>

      {/* MTTR cards */}
      <div className="grid gap-4 sm:grid-cols-4">
        {(["critical", "high", "medium", "low"] as const).map((sev) => (
          <div
            key={sev}
            className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4"
          >
            <p className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
              Avg fix time — {sev}
            </p>
            <p className={`mt-2 text-2xl font-bold tabular-nums ${MTTR_COLOUR[sev]}`}>
              {mttr[sev] != null ? `${mttr[sev]}d` : "—"}
            </p>
            <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">average days to fix</p>
          </div>
        ))}
      </div>
    </div>
  )
}
