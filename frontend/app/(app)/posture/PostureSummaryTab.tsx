"use client"

import * as React from "react"

import type {
  PostureSnapshotResponse,
  PostureTrendResponse,
  TeamPostureItem,
} from "@/lib/client/posture-api"
import type { ComplianceFramework, ControlSummaryItem } from "@/lib/client/compliance-api"
import { SegmentedControl } from "@/components/ui/SegmentedControl"
import { Card } from "@/components/ui/Card"
import { Skeleton } from "@/components/ui/Skeleton"


const SEV_VARS = {
  critical: "var(--color-severity-critical)",
  high: "var(--color-severity-high)",
  medium: "var(--color-severity-medium)",
  low: "var(--color-severity-low)",
}

const SEV_CLASSES = {
  critical: "text-[var(--color-severity-critical)]",
  high: "text-[var(--color-severity-high)]",
  medium: "text-[var(--color-severity-medium)]",
  low: "text-[var(--color-severity-low)]",
}


const RATING_TOKENS: Record<string, { color: string; border: string; bg: string }> = {
  Severe: {
    color: "var(--color-severity-critical)",
    border: "border-[var(--color-severity-critical)]/15",
    bg: "bg-[var(--color-severity-critical)]/[0.04]",
  },
  High: {
    color: "var(--color-severity-high)",
    border: "border-[var(--color-severity-high)]/15",
    bg: "bg-[var(--color-severity-high)]/[0.04]",
  },
  Moderate: {
    color: "var(--color-severity-medium)",
    border: "border-[var(--color-severity-medium)]/15",
    bg: "bg-[var(--color-severity-medium)]/[0.03]",
  },
}
const DEFAULT_RATING = {
  color: "var(--color-status-ok)",
  border: "border-[var(--color-status-ok)]/15",
  bg: "bg-[var(--color-status-ok)]/[0.04]",
}

function getRatingTokens(rating: string) {
  return RATING_TOKENS[rating] ?? DEFAULT_RATING
}


type SparkDirection = "up" | "down" | "flat"

function sparkPath(values: number[], w: number, h: number, pad = 2): string {
  if (values.length < 2) return ""
  const min = Math.min(...values)
  const max = Math.max(...values)
  const range = max - min || 1
  const step = w / (values.length - 1)
  return values
    .map((v, i) => {
      const x = i * step
      const y = h - pad - ((v - min) / range) * (h - pad * 2)
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`
    })
    .join(" ")
}

function Sparkline({
  values,
  stroke,
  className = "h-6 w-20",
}: {
  values: number[] | null
  stroke: string
  className?: string
}) {
  const w = 80
  const h = 24
  if (!values || values.length < 2) {
    return (
      <svg viewBox={`0 0 ${w} ${h}`} className={className} preserveAspectRatio="none" aria-hidden="true">
        <line
          x1="0"
          y1={h / 2}
          x2={w}
          y2={h / 2}
          stroke="var(--color-text-tertiary)"
          strokeWidth="1"
          strokeDasharray="3 3"
          opacity="0.5"
          vectorEffect="non-scaling-stroke"
        />
      </svg>
    )
  }
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className={className} preserveAspectRatio="none" aria-hidden="true">
      <path
        d={sparkPath(values, w, h)}
        fill="none"
        stroke={stroke}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  )
}


function DeltaBadge({
  direction,
  label,
  upIsBad = true,
}: {
  direction: SparkDirection
  label: string
  upIsBad?: boolean
}) {
  let arrow: string
  let color: string
  if (direction === "up") {
    arrow = "▲"
    color = upIsBad
      ? "text-[var(--color-severity-critical)]"
      : "text-[var(--color-status-ok)]"
  } else if (direction === "down") {
    arrow = "▼"
    color = upIsBad
      ? "text-[var(--color-status-ok)]"
      : "text-[var(--color-severity-critical)]"
  } else {
    arrow = "—"
    color = "text-[var(--color-text-tertiary)]"
  }
  return (
    <span className={`inline-flex items-center gap-1 text-2xs font-semibold tabular-nums ${color}`}>
      <span aria-hidden="true">{arrow}</span>
      <span>{label}</span>
    </span>
  )
}

function deriveDelta(
  series: number[] | null,
  upIsBad = true,
): { direction: SparkDirection; label: string; upIsBad: boolean } | null {
  if (!series || series.length < 2) return null
  const first = series[0]
  const last = series[series.length - 1]
  const diff = last - first
  if (diff === 0) return { direction: "flat", label: "same", upIsBad }
  if (diff > 0) return { direction: "up", label: `+${diff}`, upIsBad }
  return { direction: "down", label: `${diff}`, upIsBad }
}


function RiskScoreHero({ snap, trend }: { snap: PostureSnapshotResponse; trend: PostureTrendResponse }) {
  const { riskScore } = snap
  const { color, border, bg } = getRatingTokens(riskScore.rating)

  // Sparkline values from the trend window, last 90 points.
  const sparkPoints = trend.points.slice(-90)
  const scoreSeries =
    sparkPoints.length >= 2 ? sparkPoints.map((p) => p.risk_score) : null

  // "vs last month" delta — compare the last point to the point ~30 days back.
  // If we don't have 30 points, fall back to the first point.
  const last = sparkPoints.length > 0 ? sparkPoints[sparkPoints.length - 1] : null
  const baselineIdx =
    sparkPoints.length >= 30 ? sparkPoints.length - 30 : 0
  const baseline = sparkPoints.length > 0 ? sparkPoints[baselineIdx] : null
  let deltaNode: React.ReactNode = null
  if (last && baseline && last !== baseline) {
    const diff = last.risk_score - baseline.risk_score
    if (diff === 0) {
      deltaNode = (
        <span className="text-xs text-[var(--color-text-tertiary)]">Same as last month</span>
      )
    } else {
      // Higher score = worse. Down arrow = improvement (good).
      const isImproving = diff < 0
      const arrow = isImproving ? "▼" : "▲"
      const tone = isImproving
        ? "text-[var(--color-status-ok)]"
        : "text-[var(--color-severity-high)]"
      const label = isImproving ? "getting better" : "getting worse"
      deltaNode = (
        <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${tone}`}>
          <span aria-hidden="true">{arrow}</span>
          <span className="tabular-nums">{Math.abs(diff)} points</span>
          <span className="text-[var(--color-text-secondary)]">vs last month, {label}</span>
        </span>
      )
    }
  }

  return (
    <div className={`rounded-2xl border ${border} ${bg} overflow-hidden`}>
      <div className="px-6 pt-5 pb-4">
        <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
          Aegis Risk Score
        </p>
        <div className="mt-2 flex items-baseline gap-3">
          <span
            className="text-5xl font-semibold leading-none tabular-nums tracking-tight"
            style={{ color }}
          >
            {riskScore.score}
          </span>
          <span className="text-xl font-medium text-[var(--color-text-secondary)]">/ 100</span>
          <span className="text-sm font-semibold" style={{ color }}>
            {riskScore.rating}
          </span>
        </div>
        {deltaNode && <div className="mt-2">{deltaNode}</div>}

        <div className="mt-5 border-t border-[var(--color-border)] pt-4">
          <p className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
            90-day trend
          </p>
          <div className="mt-2">
            <Sparkline
              values={scoreSeries}
              stroke={color}
              className="h-12 w-full"
            />
          </div>
        </div>
      </div>
    </div>
  )
}


function KpiCard({
  label,
  value,
  unit,
  detail,
  spark,
  sparkStroke,
  delta,
}: {
  label: string
  value: string
  unit?: string
  detail?: React.ReactNode
  spark: number[] | null
  sparkStroke: string
  delta: { direction: SparkDirection; label: string; upIsBad?: boolean } | null
}) {
  return (
    <Card padding="none" className="px-5 py-3">
      <div className="flex items-start justify-between gap-2">
        <p className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
          {label}
        </p>
        {delta && (
          <DeltaBadge direction={delta.direction} label={delta.label} upIsBad={delta.upIsBad} />
        )}
      </div>
      <p className="mt-2 text-2xl font-semibold leading-none tabular-nums text-[var(--color-text-primary)]">
        {value}
        {unit && (
          <span className="ml-0.5 text-base font-medium text-[var(--color-text-secondary)]">
            {unit}
          </span>
        )}
      </p>
      {detail && (
        <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">{detail}</p>
      )}
      <div className="mt-2">
        <Sparkline values={spark} stroke={sparkStroke} />
      </div>
    </Card>
  )
}


function KpiGrid({ snap, trend }: { snap: PostureSnapshotResponse; trend: PostureTrendResponse }) {
  const { counts, remediation: rem, repositoryCoverage: cov } = snap

  const sparkPoints = trend.points.slice(-30)
  const criticalSeries = sparkPoints.length >= 2 ? sparkPoints.map((p) => p.critical) : null
  const criticalDelta = deriveDelta(criticalSeries, true)

  const coveragePct = Math.round(cov.percentage)

  return (
    <div className="grid grid-cols-2 gap-3">
      <KpiCard
        label="Critical findings"
        value={counts.critical.toLocaleString()}
        spark={criticalSeries}
        sparkStroke="var(--color-severity-critical)"
        delta={criticalDelta}
      />

      <KpiCard
        label="MTTR"
        value={rem.avgDays != null ? `${rem.avgDays}` : "—"}
        unit={rem.avgDays != null ? "d" : undefined}
        detail={
          rem.medianDays != null ? (
            <>
              Median{" "}
              <strong className="font-semibold text-[var(--color-text-primary)]">
                {rem.medianDays}d
              </strong>
            </>
          ) : rem.avgDays == null ? (
            "No remediations recorded yet"
          ) : undefined
        }
        spark={null}
        sparkStroke="var(--color-status-ok)"
        delta={null}
      />

      <KpiCard
        label="SLA compliance"
        value="—"
        detail="Ships with SLA analytics"
        spark={null}
        sparkStroke="var(--color-severity-medium)"
        delta={null}
      />

      <KpiCard
        label="Scan coverage"
        value={`${coveragePct}`}
        unit="%"
        detail={
          <>
            <strong className="font-semibold text-[var(--color-text-primary)]">
              {cov.total - cov.affected}
            </strong>
            {" / "}
            <strong className="font-semibold text-[var(--color-text-primary)]">
              {cov.total}
            </strong>
            {" repos clean"}
          </>
        }
        spark={null}
        sparkStroke="var(--color-text-tertiary)"
        delta={null}
      />
    </div>
  )
}


type AttentionTone = "critical" | "high" | "medium"

const ATTENTION_TONE_BG: Record<AttentionTone, string> = {
  critical: "bg-[var(--color-severity-critical)]/10 text-[var(--color-severity-critical)]",
  high: "bg-[var(--color-severity-high)]/10 text-[var(--color-severity-high)]",
  medium: "bg-[var(--color-severity-medium)]/10 text-[var(--color-severity-medium)]",
}

interface AttentionRow {
  tone: AttentionTone
  icon: "shield" | "warning" | "info"
  title: string
  sub: string
}

function AttentionIcon({ kind, className }: { kind: AttentionRow["icon"]; className?: string }) {
  const cls = className ?? "h-4 w-4"
  if (kind === "shield") {
    return (
      <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className={cls}
        aria-hidden="true"
      >
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    )
  }
  if (kind === "warning") {
    return (
      <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className={cls}
        aria-hidden="true"
      >
        <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
        <line x1="12" y1="9" x2="12" y2="13" />
        <line x1="12" y1="17" x2="12.01" y2="17" />
      </svg>
    )
  }
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={cls}
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="8" x2="12" y2="12" />
      <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
  )
}

function AttentionPanel({
  snap,
  teams,
}: {
  snap: PostureSnapshotResponse
  teams: TeamPostureItem[] | null
}) {
  if (teams === null) {
    return (
      <Card className="rounded-2xl">
        <p className="text-base font-semibold text-[var(--color-text-primary)] mb-4">
          Needs attention
        </p>
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="flex items-start gap-3">
              <span className="h-7 w-7 shrink-0 rounded-lg motion-safe:animate-pulse bg-[var(--color-surface-raised)]" />
              <div className="flex-1">
                <Skeleton className="h-4 w-3/4" />
                <Skeleton className="mt-1.5 h-3 w-1/2" />
              </div>
            </div>
          ))}
        </div>
      </Card>
    )
  }

  const rows: AttentionRow[] = []

  // Row 1: top repo with critical findings
  const topCritical = snap.topRepositories.find((r) => r.critical > 0)
  if (topCritical) {
    rows.push({
      tone: "critical",
      icon: "shield",
      title: `${topCritical.critical} critical finding${topCritical.critical !== 1 ? "s" : ""} in ${topCritical.name}`,
      sub: "Requires immediate review",
    })
  }

  // Row 2: top team backlog
  if (teams.length > 0) {
    const top = teams[0]
    const sum = top.counts.critical + top.counts.high
    if (sum > 10) {
      rows.push({
        tone: "high",
        icon: "warning",
        title: `${top.team_name} backlog growing: ${sum} open`,
        sub: "Critical + high combined",
      })
    }
  }

  // Row 3: AgeBuckets fold-in — 90+ day findings
  const overNinety = snap.ageBuckets[3]?.count ?? 0
  if (overNinety > 0) {
    rows.push({
      tone: "high",
      icon: "warning",
      title: `${overNinety.toLocaleString()} findings open over 90 days`,
      sub: "Review aging backlog",
    })
  }

  // Row 4: repos with open findings
  if (snap.repositoryCoverage.affected > 0) {
    rows.push({
      tone: "medium",
      icon: "info",
      title: `${snap.repositoryCoverage.affected} repo${snap.repositoryCoverage.affected !== 1 ? "s" : ""} currently have open findings`,
      sub: "Review affected repositories",
    })
  }

  return (
    <Card padding="none" className="rounded-2xl">
      <div className="px-5 pt-5 pb-3">
        <p className="text-base font-semibold text-[var(--color-text-primary)]">Needs attention</p>
      </div>
      {rows.length === 0 ? (
        <p className="px-5 pb-5 text-sm text-[var(--color-text-secondary)]">
          Nothing urgent. Posture is healthy.
        </p>
      ) : (
        <div>
          {rows.map((row, i) => (
            <div
              key={i}
              className="grid grid-cols-[28px_1fr_auto] items-center gap-3 border-t border-[var(--color-border)] px-5 py-3"
            >
              <div
                className={`flex h-7 w-7 items-center justify-center rounded-lg ${ATTENTION_TONE_BG[row.tone]}`}
              >
                <AttentionIcon kind={row.icon} />
              </div>
              <div className="min-w-0">
                <p className="text-sm font-medium text-[var(--color-text-primary)] truncate">
                  {row.title}
                </p>
                <p className="text-xs text-[var(--color-text-secondary)] truncate">{row.sub}</p>
              </div>
              <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                className="h-4 w-4 text-[var(--color-text-tertiary)]"
                aria-hidden="true"
              >
                <path d="m9 18 6-6-6-6" />
              </svg>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}


function IntegrationActivityStrip({ snap }: { snap: PostureSnapshotResponse }) {
  const { remediation } = snap

  type Cell =
    | { label: string; value: string; detail?: React.ReactNode; placeholder?: false }
    | { label: string; placeholder: true }

  const cells: Cell[] = [
    { label: "Slack alerts", placeholder: true },
    { label: "Webhook events", placeholder: true },
    { label: "Jira tickets", placeholder: true },
    { label: "Fix PRs opened", placeholder: true },
    {
      label: "Findings resolved",
      value: remediation.totalFixed.toLocaleString(),
      detail: (
        <>
          <strong className="font-semibold text-[var(--color-text-primary)]">
            {remediation.fixedLast30d.toLocaleString()}
          </strong>{" "}
          resolved last 30 days
        </>
      ),
    },
  ]

  return (
    <Card className="rounded-2xl">
      <div className="flex items-center justify-between gap-3 mb-4">
        <p className="text-base font-semibold text-[var(--color-text-primary)]">
          Integration activity (this month)
        </p>
        <a
          href="/notifications"
          className="text-xs text-[var(--color-accent)] hover:underline"
        >
          Manage notifications →
        </a>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {cells.map((cell) => (
          <div
            key={cell.label}
            className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3"
          >
            <p className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
              {cell.label}
            </p>
            {"placeholder" in cell && cell.placeholder ? (
              <p className="mt-2 text-2xl font-semibold leading-none tabular-nums text-[var(--color-text-tertiary)]">
                —
              </p>
            ) : (
              <>
                <p className="mt-2 text-2xl font-semibold leading-none tabular-nums text-[var(--color-text-primary)]">
                  {cell.value}
                </p>
                {cell.detail && (
                  <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
                    {cell.detail}
                  </p>
                )}
              </>
            )}
          </div>
        ))}
      </div>
      <p className="mt-3 text-xs italic text-[var(--color-text-tertiary)]">
        Delivery metrics for Slack, Webhook, Jira, and Fix PRs ship in a follow-up.
      </p>
    </Card>
  )
}


type StackLayer = "low" | "medium" | "high" | "critical"

const STACK_ORDER: StackLayer[] = ["low", "medium", "high", "critical"]

const STACK_FILL: Record<StackLayer, { color: string; opacity: number }> = {
  low:      { color: "var(--color-severity-low)",      opacity: 0.55 },
  medium:   { color: "var(--color-severity-medium)",   opacity: 0.60 },
  high:     { color: "var(--color-severity-high)",     opacity: 0.75 },
  critical: { color: "var(--color-severity-critical)", opacity: 0.85 },
}

function PostureTrendChart({
  snap,
  trend,
}: {
  snap: PostureSnapshotResponse
  trend: PostureTrendResponse
}) {
  const [hoverIdx, setHoverIdx] = React.useState<number | null>(null)
  // Use the last 30 points for the executive view; the full trend is in Breakdown.
  const points = trend.points.slice(-30)
  if (points.length < 2) {
    return (
      <Card className="rounded-2xl">
        <p className="text-base font-semibold text-[var(--color-text-primary)]">
          Open findings by severity — 30 days
        </p>
        <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
          Not enough data to plot a trend yet.
        </p>
      </Card>
    )
  }

  // Chart geometry — render to a viewBox of 720×260; preserveAspectRatio="none"
  // lets it fill the card width.
  const PLOT_X = 40
  const PLOT_W = 680
  const PLOT_H = 190
  const VIEW_W = 720
  const VIEW_H = 260
  const step = PLOT_W / (points.length - 1)

  // Build cumulative totals so each layer's top line sits above the previous.
  const cumulative: number[][] = points.map(() => [0, 0, 0, 0])
  STACK_ORDER.forEach((layer, idx) => {
    points.forEach((p, i) => {
      const previous = idx === 0 ? 0 : cumulative[i][idx - 1]
      cumulative[i][idx] = previous + p[layer]
    })
  })
  const maxTotal = Math.max(...points.map((p) => p.total), 1)

  function yOf(value: number): number {
    return PLOT_H - (value / maxTotal) * PLOT_H
  }

  function areaPath(layerIdx: number): string {
    const top = points
      .map((_, i) => `${i === 0 ? "M" : "L"}${(i * step).toFixed(1)},${yOf(cumulative[i][layerIdx]).toFixed(1)}`)
      .join(" ")
    const baseY = layerIdx === 0
      ? yOf(0)
      : NaN // unused; we use bottom for layer 0
    let bottom: string
    if (layerIdx === 0) {
      bottom = ` L${PLOT_W.toFixed(1)},${yOf(0).toFixed(1)} L0,${yOf(0).toFixed(1)} Z`
    } else {
      // Reverse along the previous layer's top
      const back = points
        .map((_, i) => {
          const idx = points.length - 1 - i
          return `L${(idx * step).toFixed(1)},${yOf(cumulative[idx][layerIdx - 1]).toFixed(1)}`
        })
        .join(" ")
      bottom = ` ${back} Z`
    }
    return top + bottom
    // The literal `baseY` binding above silences ESLint; intentionally unused for layer 0.
  }

  // Y-axis ticks (4 lines)
  const gridSteps = [0.25, 0.5, 0.75, 1.0]

  // Map a pointer position over the plot to the nearest data-point index.
  function idxFromPointer(e: React.PointerEvent<HTMLDivElement>) {
    const rect = e.currentTarget.getBoundingClientRect()
    if (rect.width === 0) return
    const frac = Math.min(Math.max((e.clientX - rect.left) / rect.width, 0), 1)
    setHoverIdx(Math.round(frac * (points.length - 1)))
  }

  const hovered = hoverIdx !== null ? points[hoverIdx] : null
  // Crosshair / tooltip x as a percentage of the full SVG width so it lines up
  // regardless of the (non-uniform) container scaling.
  const hoverLeftPct =
    hoverIdx !== null ? ((PLOT_X + hoverIdx * step) / VIEW_W) * 100 : 0
  // Keep the tooltip card on-screen near the edges.
  const tooltipAlign =
    hoverIdx === null
      ? "-translate-x-1/2"
      : hoverIdx <= 2
        ? "translate-x-0"
        : hoverIdx >= points.length - 3
          ? "-translate-x-full"
          : "-translate-x-1/2"

  return (
    <Card className="rounded-2xl">
      <div className="flex items-center justify-between gap-3 mb-3">
        <p className="text-base font-semibold text-[var(--color-text-primary)]">
          Open findings by severity — 30 days
        </p>
      </div>
      <div className="relative">
      <svg
        viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
        className="w-full h-56"
        preserveAspectRatio="none"
        role="img"
        aria-label="Stacked-area chart of open findings by severity over the last 30 days"
      >
        {/* Gridlines */}
        <g stroke="var(--color-border)" strokeWidth="1" strokeDasharray="2 4">
          {gridSteps.map((g) => (
            <line key={g} x1={PLOT_X} y1={yOf(maxTotal * g)} x2={VIEW_W} y2={yOf(maxTotal * g)} />
          ))}
        </g>
        {/* Y-axis labels */}
        <g fontSize="10" fill="var(--color-text-tertiary)">
          {gridSteps.map((g) => (
            <text key={g} x="0" y={yOf(maxTotal * g) + 4}>
              {Math.round(maxTotal * g)}
            </text>
          ))}
        </g>
        {/* Plot */}
        <g transform={`translate(${PLOT_X}, 0)`}>
          {STACK_ORDER.map((layer, idx) => (
            <path
              key={layer}
              d={areaPath(idx)}
              fill={STACK_FILL[layer].color}
              fillOpacity={STACK_FILL[layer].opacity}
            />
          ))}
          {/* "Today" reference line */}
          <line
            x1={PLOT_W}
            y1="0"
            x2={PLOT_W}
            y2={PLOT_H}
            stroke="var(--color-accent)"
            strokeWidth="1"
            strokeDasharray="2 3"
            opacity="0.6"
          />
          {/* Hover crosshair */}
          {hoverIdx !== null && (
            <line
              x1={hoverIdx * step}
              y1="0"
              x2={hoverIdx * step}
              y2={PLOT_H}
              stroke="var(--color-text-secondary)"
              strokeWidth="1"
              vectorEffect="non-scaling-stroke"
            />
          )}
        </g>
        {/* X-axis labels: first / mid / last + Today */}
        <g fontSize="10" fill="var(--color-text-tertiary)">
          <text x={PLOT_X} y={VIEW_H - 10}>{points[0].date}</text>
          <text x={PLOT_X + PLOT_W / 2} y={VIEW_H - 10} textAnchor="middle">
            {points[Math.floor(points.length / 2)].date}
          </text>
          <text x={PLOT_X + PLOT_W} y={VIEW_H - 10} textAnchor="end" fill="var(--color-accent)">
            Today
          </text>
        </g>
      </svg>
      {/* Pointer capture region over the plot (excludes the axis gutters). */}
      <div
        className="absolute inset-y-0 cursor-crosshair"
        style={{
          left: `${(PLOT_X / VIEW_W) * 100}%`,
          width: `${(PLOT_W / VIEW_W) * 100}%`,
        }}
        onPointerMove={idxFromPointer}
        onPointerLeave={() => setHoverIdx(null)}
      />
      {/* Hover tooltip */}
      {hovered && (
        <div
          className={`pointer-events-none absolute top-1 z-10 ${tooltipAlign}`}
          style={{ left: `${hoverLeftPct}%` }}
        >
          <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 shadow-lg">
            <p className="mb-1.5 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
              {hovered.date}
            </p>
            <div className="space-y-1">
              {(["critical", "high", "medium", "low"] as const).map((sev) => (
                <div key={sev} className="flex items-center gap-2 text-xs whitespace-nowrap">
                  <span
                    className="h-2.5 w-2.5 rounded-sm shrink-0"
                    style={{ background: SEV_VARS[sev] }}
                    aria-hidden="true"
                  />
                  <span className="capitalize text-[var(--color-text-secondary)]">{sev}</span>
                  <span className="ml-auto pl-3 font-semibold tabular-nums text-[var(--color-text-primary)]">
                    {hovered[sev].toLocaleString()}
                  </span>
                </div>
              ))}
              <div className="mt-1 flex items-center gap-2 border-t border-[var(--color-border)] pt-1 text-xs">
                <span className="text-[var(--color-text-secondary)]">Total</span>
                <span className="ml-auto pl-3 font-semibold tabular-nums text-[var(--color-text-primary)]">
                  {hovered.total.toLocaleString()}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}
      </div>
      {/* Legend with current totals (replaces SeverityDonut in summary) */}
      <div className="mt-2 flex flex-wrap items-center gap-4 text-xs text-[var(--color-text-secondary)]">
        {(["critical", "high", "medium", "low"] as const).map((sev) => (
          <span key={sev} className="inline-flex items-center gap-1.5">
            <span
              className="h-2.5 w-2.5 rounded-sm"
              style={{ background: SEV_VARS[sev] }}
              aria-hidden="true"
            />
            <span className="capitalize">{sev}</span>
            <span className="font-semibold tabular-nums text-[var(--color-text-primary)]">
              {snap.counts[sev].toLocaleString()}
            </span>
          </span>
        ))}
      </div>
    </Card>
  )
}


type TeamView = "teams" | "repos"

interface TeamRowVM {
  key: string
  label: string
  bar: number
  barColor: string
  count: number
}

function TeamRiskPanel({
  snap,
  teams,
}: {
  snap: PostureSnapshotResponse
  teams: TeamPostureItem[] | null
}) {
  const [teamView, setTeamView] = React.useState<TeamView>("teams")

  let rows: TeamRowVM[] | null = null
  let emptyMessage = ""

  if (teamView === "teams") {
    if (teams === null) {
      rows = null
    } else if (teams.length === 0) {
      rows = []
      emptyMessage = "Team data not configured."
    } else {
      const slice = teams.slice(0, 6)
      const maxScore = Math.max(...slice.map((t) => t.risk_score.score), 1)
      rows = slice.map((team) => ({
        key: team.team_id,
        label: team.team_name,
        bar: maxScore > 0 ? Math.max(team.risk_score.score / maxScore, 0.08) : 0.08,
        barColor: getRatingTokens(team.risk_score.rating).color,
        count: team.counts.critical + team.counts.high,
      }))
    }
  } else {
    const slice = snap.topRepositories.slice(0, 6)
    if (slice.length === 0) {
      rows = []
      emptyMessage = "No repository data yet."
    } else {
      const maxOpen = Math.max(...slice.map((r) => r.open), 1)
      rows = slice.map((repo) => ({
        key: repo.name,
        label: repo.name,
        bar: Math.max(repo.open / maxOpen, 0.08),
        barColor: SEV_VARS.high,
        count: repo.critical + repo.high,
      }))
    }
  }

  return (
    <Card className="rounded-2xl">
      <div className="flex items-center justify-between gap-3 mb-4">
        <p className="text-base font-semibold text-[var(--color-text-primary)]">
          Risk by team
        </p>
        <SegmentedControl
          ariaLabel="Risk view"
          size="xs"
          value={teamView}
          onChange={(id) => setTeamView(id)}
          options={[
            { id: "teams", label: "Teams" },
            { id: "repos", label: "Repos" },
          ]}
        />
      </div>

      {rows === null ? (
        <div className="space-y-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3">
              <Skeleton className="h-3 w-24" />
              <Skeleton className="h-2 flex-1 rounded-full" />
              <Skeleton className="h-3 w-6" />
            </div>
          ))}
        </div>
      ) : rows.length === 0 ? (
        <p className="text-sm text-[var(--color-text-secondary)]">{emptyMessage}</p>
      ) : (
        <div className="space-y-3">
          {rows.map((row) => (
            <div key={row.key} className="flex items-center gap-3">
              <span
                className="min-w-[96px] text-xs font-medium text-[var(--color-text-primary)] truncate"
                title={row.label}
              >
                {row.label}
              </span>
              <div className="h-2 flex-1 overflow-hidden rounded-full bg-[var(--color-surface-raised)]">
                <div
                  className="h-full rounded-full"
                  title={`${row.label}: ${row.count.toLocaleString()} critical + high`}
                  style={{ width: `${row.bar * 100}%`, background: row.barColor }}
                />
              </div>
              <span className="min-w-[28px] text-right text-xs tabular-nums font-medium text-[var(--color-text-secondary)]">
                {row.count}
              </span>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}


function ComplianceSnapshot({
  frameworks,
  summaries,
}: {
  frameworks: ComplianceFramework[] | null
  summaries: Record<string, ControlSummaryItem[]>
}) {
  const slots = Array.from({ length: 4 }, (_, i) => (frameworks ? frameworks[i] ?? null : undefined))

  function statusBadge(controls: ControlSummaryItem[]): React.ReactNode {
    const total = controls.length
    if (total === 0) return null
    const passing = controls.filter((c) => c.finding_count === 0).length
    const pct = passing / total

    if (pct >= 0.95) {
      return (
        <span className="inline-flex items-center rounded-full px-2 py-0.5 text-2xs font-semibold bg-[var(--color-status-ok)]/10 text-[var(--color-status-ok)]">
          On track
        </span>
      )
    }
    if (pct >= 0.8) {
      return (
        <span className="inline-flex items-center rounded-full px-2 py-0.5 text-2xs font-semibold bg-[var(--color-severity-medium)]/15 text-[var(--color-severity-medium)]">
          Partial
        </span>
      )
    }
    return (
      <span className="inline-flex items-center rounded-full px-2 py-0.5 text-2xs font-semibold bg-[var(--color-severity-critical)]/15 text-[var(--color-severity-critical)]">
        At risk
      </span>
    )
  }

  return (
    <div>
      <p className="text-base font-semibold text-[var(--color-text-primary)] mb-4">
        Compliance posture
      </p>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        {slots.map((fw, i) => {
          if (fw === undefined) {
            return (
              <Skeleton
                key={i}
                className="h-24 rounded-2xl"
              />
            )
          }
          if (fw === null) {
            return (
              <Card key={i} padding="none" className="rounded-2xl px-5 py-4">
                <p className="text-xs font-semibold text-[var(--color-text-tertiary)]">
                  No framework
                </p>
              </Card>
            )
          }
          const controls = summaries[fw.id]
          if (!controls) {
            return (
              <Card key={fw.id} padding="none" className="rounded-2xl px-5 py-4">
                <p className="text-xs font-semibold text-[var(--color-text-primary)]">{fw.label}</p>
                <Skeleton className="mt-3 h-4 w-16" />
                <Skeleton className="mt-2 h-3 w-24" />
              </Card>
            )
          }
          const passing = controls.filter((c) => c.finding_count === 0).length
          const total = controls.length
          return (
            <Card key={fw.id} padding="none" className="rounded-2xl px-5 py-4">
              <p className="text-xs font-semibold text-[var(--color-text-primary)]">{fw.label}</p>
              <div className="mt-2">{statusBadge(controls)}</div>
              <p className="mt-2 text-2xs text-[var(--color-text-tertiary)]">
                {passing} of {total} controls
              </p>
            </Card>
          )
        })}
      </div>
    </div>
  )
}


function VerdictAssurance({ snap }: { snap: PostureSnapshotResponse }) {
  const cov = snap.repositoryCoverage
  return (
    <div className="space-y-3">
      <div className="rounded-xl border border-[var(--color-status-ok)]/30 bg-[var(--color-status-ok)]/10 p-3">
        <p className="text-xs font-medium text-[var(--color-status-ok)]">
          {cov.total} repo{cov.total !== 1 ? "s" : ""} under coverage · sources healthy
        </p>
      </div>

      {cov.affected > 0 && (
        <div className="rounded-xl border border-[var(--color-severity-medium)]/30 bg-[var(--color-severity-medium)]/10 p-3">
          <p className="text-xs font-medium text-[var(--color-severity-medium)]">
            {cov.affected} repo{cov.affected !== 1 ? "s" : ""} currently have open findings
          </p>
        </div>
      )}

      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-3">
        <p className="text-xs font-medium text-[var(--color-text-secondary)]">
          Covers scanned source code only — runtime not directly observed.
        </p>
      </div>
    </div>
  )
}


export interface PostureSummaryTabProps {
  snap: PostureSnapshotResponse
  trend: PostureTrendResponse
  teams: TeamPostureItem[] | null
  frameworks: ComplianceFramework[] | null
  complianceSummaries: Record<string, ControlSummaryItem[]>
}

export function PostureSummaryTab({
  snap,
  trend,
  teams,
  frameworks,
  complianceSummaries,
}: PostureSummaryTabProps) {
  return (
    <div className="px-6 py-5 space-y-5">
      {/* Beat 1 */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <RiskScoreHero snap={snap} trend={trend} />
        <KpiGrid snap={snap} trend={trend} />
      </div>

      {/* Beat 2 */}
      <AttentionPanel snap={snap} teams={teams} />

      {/* Beat 3 */}
      <IntegrationActivityStrip snap={snap} />

      {/* Beat 4 */}
      <div className="grid lg:grid-cols-2 gap-5">
        <PostureTrendChart snap={snap} trend={trend} />
        <TeamRiskPanel snap={snap} teams={teams} />
      </div>

      {/* Beat 5 */}
      <ComplianceSnapshot frameworks={frameworks} summaries={complianceSummaries} />

      {/* Beat 6 */}
      <VerdictAssurance snap={snap} />
    </div>
  )
}
