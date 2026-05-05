import type { SecretsTrendEntry } from "@/lib/shared/secrets/types"

const MIN_COL_WIDTH = 60
const HEIGHT = 320
const PADDING = { top: 28, right: 28, bottom: 68, left: 56 }

function yFor(value: number, max: number, plotHeight: number) {
  if (max <= 0) return PADDING.top + plotHeight
  return PADDING.top + plotHeight - (value / max) * plotHeight
}

function formatDelta(value: number) {
  if (value === 0) return "No change"
  return `${value > 0 ? "+" : ""}${value} vs prior month`
}

export function BacklogHealthChart({ trend }: { trend: SecretsTrendEntry[] }) {
  if (trend.length === 0) {
    return (
      <div className="flex min-h-40 items-center justify-center rounded-2xl border border-dashed border-[var(--color-border)] text-sm text-[var(--color-text-secondary)]">
        Not enough trend data to display yet.
      </div>
    )
  }

  const chartWidth = Math.max(560, (trend.length - 1) * MIN_COL_WIDTH + PADDING.left + PADDING.right)
  const plotWidth = chartWidth - PADDING.left - PADDING.right
  const plotHeight = HEIGHT - PADDING.top - PADDING.bottom
  const xStep = trend.length > 1 ? plotWidth / (trend.length - 1) : 0
  const maxY = Math.max(1, ...trend.map((e) => e.endOfMonth.unresolved))
  const displayMaxY = Math.max(1, Math.ceil(maxY * 1.15))
  const ticks = Array.from({ length: 5 }, (_, i) => Math.round((displayMaxY / 4) * i))
  const baselineY = PADDING.top + plotHeight
  const latestEntry = trend.at(-1)
  const previousEntry = trend.at(-2)
  const latestPointLabel = latestEntry ? latestEntry.month : "Latest month"
  const latestValue = latestEntry?.endOfMonth.unresolved ?? 0
  const latestDelta = latestValue - (previousEntry?.endOfMonth.unresolved ?? latestValue)
  const latestDeltaTone =
    latestDelta < 0
      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
      : latestDelta > 0
        ? "border-red-500/30 bg-red-500/10 text-red-400"
        : "border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-secondary)]"

  const points = trend.map((entry, index) => {
    const x = PADDING.left + (trend.length > 1 ? index * xStep : plotWidth / 2)
    const y = yFor(entry.endOfMonth.unresolved, displayMaxY, plotHeight)
    return { x, y }
  })
  const latest = trend.at(-1)
  const latestPoint = points[points.length - 1]

  const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x} ${p.y}`).join(" ")
  const areaPath = [
    `M ${points[0].x} ${baselineY}`,
    ...points.map((p) => `L ${p.x} ${p.y}`),
    `L ${points[points.length - 1].x} ${baselineY}`,
    "Z",
  ].join(" ")

  const gradientId = "backlog-gradient"

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-4 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4 shadow-[0_12px_36px_rgba(15,23,42,0.06)]">
        <div>
          <p className="text-sm font-semibold text-[var(--color-text-primary)]">Unresolved exposure</p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            Total open findings over time. A downward slope indicates progress.
          </p>
          {latest ? (
            <p className="mt-3 text-xs font-medium text-[var(--color-accent)]">
              Latest point: {latest.endOfMonth.unresolved} open findings in {latest.month}
            </p>
          ) : null}
        </div>
        <div className="grid gap-2 sm:grid-cols-2">
          <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3">
            <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-[var(--color-text-secondary)]">Peak backlog</p>
            <p className="mt-2 text-2xl font-semibold text-[var(--color-text-primary)]">{maxY}</p>
          </div>
          <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3">
            <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-[var(--color-text-secondary)]">Trend direction</p>
            <p className={`mt-2 text-2xl font-semibold ${latestDelta < 0 ? "text-emerald-400" : latestDelta > 0 ? "text-red-400" : "text-[var(--color-text-primary)]"}`}>
              {latestDelta < 0 ? "Down" : latestDelta > 0 ? "Up" : "Flat"}
            </p>
          </div>
        </div>
      </div>

      <div className="flex gap-4 rounded-3xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4 shadow-[0_18px_50px_rgba(15,23,42,0.06)]">
        {/* direction:rtl makes overflow-x-auto start scrolled to the right (newest month visible by default) */}
        <div className="min-w-0 flex-1 overflow-x-auto" style={{ direction: "rtl" }}>
        <svg
          width={chartWidth}
          height={HEIGHT}
          viewBox={`0 0 ${chartWidth} ${HEIGHT}`}
          className="block"
          style={{ direction: "ltr" }}
          role="img"
          aria-label="Active backlog over time with the latest month emphasized"
        >
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#f97316" stopOpacity="0.26" />
              <stop offset="100%" stopColor="#f97316" stopOpacity="0.03" />
            </linearGradient>
            <radialGradient id="backlog-glow" cx="50%" cy="50%" r="50%">
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

          <path d={areaPath} fill={`url(#${gradientId})`} />
          <path d={linePath} fill="none" stroke="#f97316" strokeWidth="3" strokeLinejoin="round" strokeLinecap="round" />

          {points.map((p, index) => {
            const isLatest = index === points.length - 1
            return (
              <g key={trend[index].month}>
                {isLatest ? <circle cx={p.x} cy={p.y} r="18" fill="url(#backlog-glow)" /> : null}
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={index === trend.length - 1 ? 6 : 4}
                  fill={index === trend.length - 1 ? "#fb923c" : "#f97316"}
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

        {/* Legend / description — pinned to the right, never scrolls */}
        <div className="flex w-40 shrink-0 flex-col justify-center gap-3 border-l border-[var(--color-border)] pl-4">
          <div>
            <p className="text-xs font-semibold text-[var(--color-text-primary)]">Unresolved exposure</p>
            <p className="mt-1 text-[11px] leading-relaxed text-[var(--color-text-secondary)]">
              Total open findings over time. A downward slope indicates progress.
            </p>
          </div>
          {latest ? (
            <div className="rounded-xl border border-[var(--color-accent)]/30 bg-[var(--color-accent-subtle)] px-3 py-2">
              <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--color-accent)]">Latest</p>
              <p className="mt-1 text-lg font-semibold text-[var(--color-accent)]">{latest.endOfMonth.unresolved}</p>
              <p className="text-[10px] text-[var(--color-text-secondary)]">{latest.month}</p>
            </div>
          ) : null}
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-[#fb923c]" />
            <span className="text-[11px] text-[var(--color-text-secondary)]">Backlog size</span>
          </div>
        </div>
      </div>
    </div>
  )
}
