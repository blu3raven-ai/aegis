"use client"

import * as React from "react"
import Link from "next/link"

import type {
  PostureSnapshotResponse,
  PostureTrendResponse,
  TeamPostureItem,
} from "@/lib/client/posture-api"
import type { ComplianceFramework, ControlSummaryItem } from "@/lib/client/compliance-api"
import type { SlaBreachSummary } from "@/lib/client/sla-api"
import { SegmentedControl } from "@/components/ui/SegmentedControl"
import { Card } from "@/components/ui/Card"
import { Skeleton } from "@/components/ui/Skeleton"
import {
  SeverityDonut,
  TopReposPanel,
  RepositoryCoveragePanel,
  AgeBucketsPanel,
} from "./PostureBreakdownPanels"
import { findingsHref } from "./posture-links"
import { Sparkline } from "@/components/shared/charts/Sparkline"
import { useMeasuredWidth } from "@/components/shared/charts/useMeasuredWidth"


/** Trend windows offered by the page-level time-range control. */
export type PostureRange = 30 | 90 | 365

const RANGE_LABEL: Record<PostureRange, string> = {
  30: "30 days",
  90: "90 days",
  365: "12 months",
}

/** Format a `YYYY-MM-DD` chart label as a compact local date ("Jun 15").
 *  Parses at local midnight to avoid the UTC off-by-one on date-only strings. */
function formatChartDate(iso: string): string {
  const d = new Date(`${iso}T00:00:00`)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" })
}


const SEV_VARS = {
  critical: "var(--color-severity-critical)",
  high: "var(--color-severity-high)",
  medium: "var(--color-severity-medium)",
  low: "var(--color-severity-low)",
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


function RiskScoreHero({
  snap,
  trend,
  rangeDays,
}: {
  snap: PostureSnapshotResponse
  trend: PostureTrendResponse
  rangeDays: PostureRange
}) {
  const { riskScore } = snap
  const { color, border, bg } = getRatingTokens(riskScore.rating)

  // Sparkline values across the selected trend window.
  const sparkPoints = trend.points
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
    <div className={`panel-ticks rounded-md border ${border} ${bg} overflow-hidden`}>
      <div className="px-6 pt-5 pb-4">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
          Risk score
        </h2>
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
        <p className="mt-1 text-2xs font-medium uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
          Lower is better
        </p>
        {deltaNode && <div className="mt-2">{deltaNode}</div>}
        {riskScore.summary && (
          <p className="mt-2 text-sm text-[var(--color-text-secondary)]">{riskScore.summary}</p>
        )}

        {scoreSeries && (
          <div className="mt-5 border-t border-[var(--color-border)] pt-4">
            <p className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
              {RANGE_LABEL[rangeDays]} trend
            </p>
            <div className="mt-2">
              <Sparkline values={scoreSeries} stroke={color} className="h-12 w-full" withArea />
            </div>
          </div>
        )}
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
  href,
}: {
  label: string
  value: string
  unit?: string
  detail?: React.ReactNode
  spark: number[] | null
  sparkStroke: string
  delta: { direction: SparkDirection; label: string; upIsBad?: boolean } | null
  /** When set, the whole card links into the scoped Findings view. */
  href?: string
}) {
  const card = (
    <Card
      padding="none"
      className={`panel-ticks h-full rounded-md px-5 py-3 ${href ? "transition-colors hover:border-[var(--color-accent)]/40" : ""}`}
    >
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
      {spark && spark.length >= 2 && (
        <div className="mt-2">
          <Sparkline values={spark} stroke={sparkStroke} />
        </div>
      )}
    </Card>
  )
  if (!href) return card
  return (
    <Link
      href={href}
      aria-label={`View ${label} in findings`}
      className="block rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
    >
      {card}
    </Link>
  )
}


function KpiGrid({
  snap,
  trend,
  slaSummary,
}: {
  snap: PostureSnapshotResponse
  trend: PostureTrendResponse
  slaSummary: SlaBreachSummary | null
}) {
  const { counts, remediation: rem } = snap

  const sparkPoints = trend.points
  const criticalSeries = sparkPoints.length >= 2 ? sparkPoints.map((p) => p.critical) : null
  const criticalDelta = deriveDelta(criticalSeries, true)

  // SLA attainment: share of findings-under-SLA still within their deadline.
  const slaTotals = slaSummary
    ? Object.values(slaSummary).reduce(
        (acc, s) => ({ open: acc.open + s.open, breached: acc.breached + s.breached }),
        { open: 0, breached: 0 },
      )
    : null
  const slaAttainment =
    slaTotals && slaTotals.open > 0
      ? Math.round(((slaTotals.open - slaTotals.breached) / slaTotals.open) * 100)
      : null
  const criticalsBreached = slaSummary?.critical.breached ?? 0

  return (
    <div className="grid grid-cols-2 gap-3">
      <KpiCard
        label="Critical findings"
        value={counts.critical.toLocaleString()}
        spark={criticalSeries}
        sparkStroke="var(--color-severity-critical)"
        delta={criticalDelta}
        href={findingsHref({ severity: "critical" })}
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
        label="Resolved (30d)"
        value={rem.fixedLast30d.toLocaleString()}
        detail={
          rem.totalFixed > 0 ? (
            <>
              <strong className="font-semibold text-[var(--color-text-primary)]">
                {rem.totalFixed.toLocaleString()}
              </strong>{" "}
              fixed all-time
            </>
          ) : (
            "No remediations recorded yet"
          )
        }
        spark={null}
        sparkStroke="var(--color-status-ok)"
        delta={null}
      />

      <KpiCard
        label="SLA attainment"
        value={slaAttainment != null ? `${slaAttainment}` : "—"}
        unit={slaAttainment != null ? "%" : undefined}
        detail={
          slaAttainment == null ? (
            "No findings under SLA yet"
          ) : criticalsBreached > 0 ? (
            <>
              <strong className="font-semibold text-[var(--color-severity-critical)]">
                {criticalsBreached.toLocaleString()}
              </strong>{" "}
              critical past SLA
            </>
          ) : slaTotals && slaTotals.breached > 0 ? (
            <>
              <strong className="font-semibold text-[var(--color-text-primary)]">
                {slaTotals.breached.toLocaleString()}
              </strong>{" "}
              past SLA
            </>
          ) : (
            "All within SLA"
          )
        }
        spark={null}
        sparkStroke="var(--color-status-ok)"
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
  /** When set, the row links into the scoped Findings view. */
  href?: string
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
  // snap is always present here; teams loads in parallel and may still be null.
  // Build the snap-derived rows immediately so they aren't hidden behind a
  // team-data skeleton; the team-backlog row is appended once teams resolves.
  const rows: AttentionRow[] = []

  const topCritical = snap.topRepositories.find((r) => r.critical > 0)
  if (topCritical) {
    rows.push({
      tone: "critical",
      icon: "shield",
      title: `${topCritical.critical} critical finding${topCritical.critical !== 1 ? "s" : ""} in ${topCritical.name}`,
      sub: "Requires immediate review",
      href: findingsHref({ repo: topCritical.name, severity: "critical" }),
    })
  }

  if (teams && teams.length > 0) {
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

  return (
    <Card padding="none" className="rounded-md">
      <div className="px-5 pt-5 pb-3">
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">Needs attention</h2>
      </div>
      {rows.length === 0 && teams !== null ? (
        <p className="px-5 pb-5 text-sm text-[var(--color-text-secondary)]">
          Nothing urgent. Posture is healthy.
        </p>
      ) : (
        <div>
          {rows.map((row, i) => {
            const inner = (
              <>
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
                {row.href && (
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
                )}
              </>
            )
            const cls = `grid items-center gap-3 border-t border-[var(--color-border)] px-5 py-3 ${
              row.href ? "grid-cols-[28px_1fr_auto]" : "grid-cols-[28px_1fr]"
            }`
            return row.href ? (
              <Link
                key={i}
                href={row.href}
                className={`${cls} transition-colors hover:bg-[var(--color-surface)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--color-accent)]`}
              >
                {inner}
              </Link>
            ) : (
              <div key={i} className={cls}>
                {inner}
              </div>
            )
          })}
          {teams === null && (
            <div
              className="grid grid-cols-[28px_1fr] items-center gap-3 border-t border-[var(--color-border)] px-5 py-3"
              aria-hidden="true"
            >
              <span className="h-7 w-7 shrink-0 rounded-lg motion-safe:animate-pulse bg-[var(--color-surface-raised)]" />
              <div className="min-w-0">
                <Skeleton className="h-4 w-3/4" />
                <Skeleton className="mt-1.5 h-3 w-1/2" />
              </div>
            </div>
          )}
        </div>
      )}
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

/** Composite risk score (0-100) over the selected window — the detail view of
 *  the small hero sparkline, with a fixed scale, date axis, and hover read-out. */
function RiskTrendChart({
  trend,
  rangeDays,
  color,
}: {
  trend: PostureTrendResponse
  rangeDays: PostureRange
  color: string
}) {
  const [hoverIdx, setHoverIdx] = React.useState<number | null>(null)
  // Sanitised: useId() returns colon-bearing ids that break SVG url(#…) refs.
  const gradId = `risk-grad-${React.useId().replace(/:/g, "")}`
  const [boxRef, W] = useMeasuredWidth<HTMLDivElement>()
  const points = trend.points
  if (points.length < 2) {
    return (
      <Card className="rounded-md">
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
          Risk score over time
        </h2>
        <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
          Not enough history to plot a trend yet.
        </p>
      </Card>
    )
  }

  // Rendered at the measured pixel width so the viewBox is 1:1 — no
  // preserveAspectRatio distortion; markers are true circles and text is crisp.
  const H = 176
  const PAD_L = 30
  const PAD_R = 10
  const PAD_T = 8
  const PAD_B = 22
  const MAX = 100
  const plotW = Math.max(W - PAD_L - PAD_R, 0)
  const plotH = H - PAD_T - PAD_B
  const xOf = (i: number) => PAD_L + (plotW * i) / (points.length - 1)
  const yOf = (v: number) => PAD_T + plotH - (v / MAX) * plotH

  const linePath = points
    .map((p, i) => `${i === 0 ? "M" : "L"}${xOf(i).toFixed(1)},${yOf(p.risk_score).toFixed(1)}`)
    .join(" ")
  const areaPath = `${linePath} L${xOf(points.length - 1).toFixed(1)},${yOf(0).toFixed(1)} L${xOf(0).toFixed(1)},${yOf(0).toFixed(1)} Z`
  const gridSteps = [0, 0.25, 0.5, 0.75, 1.0]

  function idxFromPointer(e: React.PointerEvent<HTMLDivElement>) {
    const rect = e.currentTarget.getBoundingClientRect()
    if (rect.width === 0) return
    const frac = Math.min(Math.max((e.clientX - rect.left) / rect.width, 0), 1)
    setHoverIdx(Math.round(frac * (points.length - 1)))
  }

  const hovered = hoverIdx !== null ? points[hoverIdx] : null
  const tooltipAlign =
    hoverIdx === null
      ? "-translate-x-1/2"
      : hoverIdx <= 2
        ? "translate-x-0"
        : hoverIdx >= points.length - 3
          ? "-translate-x-full"
          : "-translate-x-1/2"

  return (
    <Card className="rounded-md">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
          Risk score over time
        </h2>
        <span className="text-2xs font-medium uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
          Last {RANGE_LABEL[rangeDays]} · lower is better
        </span>
      </div>
      <div ref={boxRef} className="relative" style={{ height: H }}>
        {W > 0 && (
          <>
            <svg
              width="100%"
              height={H}
              viewBox={`0 0 ${W} ${H}`}
              className="block"
              role="img"
              aria-label={`Risk score trend over the last ${RANGE_LABEL[rangeDays]}`}
            >
              <defs>
                <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={color} stopOpacity="0.28" />
                  <stop offset="100%" stopColor={color} stopOpacity="0" />
                </linearGradient>
              </defs>
              <g stroke="var(--color-border)" strokeOpacity="0.5">
                {gridSteps.map((g) => (
                  <line key={g} x1={PAD_L} y1={yOf(MAX * g)} x2={W - PAD_R} y2={yOf(MAX * g)} />
                ))}
              </g>
              <g fontSize="10" fill="var(--color-text-secondary)">
                {gridSteps.map((g) => (
                  <text key={g} x="0" y={yOf(MAX * g) + 3.5}>
                    {Math.round(MAX * g)}
                  </text>
                ))}
              </g>
              <path d={areaPath} fill={`url(#${gradId})`} />
              <path
                d={linePath}
                fill="none"
                stroke={color}
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              {hoverIdx !== null && (
                <line
                  x1={xOf(hoverIdx)}
                  y1={PAD_T}
                  x2={xOf(hoverIdx)}
                  y2={PAD_T + plotH}
                  stroke="var(--color-text-secondary)"
                  strokeWidth="1"
                />
              )}
              <g fontSize="10" fill="var(--color-text-secondary)">
                <text x={PAD_L} y={H - 6}>{formatChartDate(points[0].date)}</text>
                <text x={PAD_L + plotW / 2} y={H - 6} textAnchor="middle">
                  {formatChartDate(points[Math.floor(points.length / 2)].date)}
                </text>
                <text x={PAD_L + plotW} y={H - 6} textAnchor="end">
                  {formatChartDate(points[points.length - 1].date)}
                </text>
              </g>
              {/* Current-value + hover markers — true round circles at 1:1. */}
              <circle
                cx={xOf(points.length - 1)}
                cy={yOf(points[points.length - 1].risk_score)}
                r="3.5"
                fill={color}
                stroke="var(--color-surface)"
                strokeWidth="2"
              />
              {hoverIdx !== null && (
                <circle
                  cx={xOf(hoverIdx)}
                  cy={yOf(points[hoverIdx].risk_score)}
                  r="4"
                  fill={color}
                  stroke="var(--color-surface)"
                  strokeWidth="2"
                />
              )}
            </svg>
            <div
              className="absolute inset-y-0 cursor-crosshair"
              style={{ left: PAD_L, width: plotW }}
              onPointerMove={idxFromPointer}
              onPointerLeave={() => setHoverIdx(null)}
            />
            {hovered && hoverIdx !== null && (
              <div
                className={`pointer-events-none absolute top-1 z-10 ${tooltipAlign}`}
                style={{ left: xOf(hoverIdx) }}
              >
                <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 shadow-lg whitespace-nowrap">
                  <p className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
                    {formatChartDate(hovered.date)}
                  </p>
                  <p className="mt-1 text-sm font-semibold tabular-nums text-[var(--color-text-primary)]">
                    {hovered.risk_score}
                    <span className="font-normal text-[var(--color-text-tertiary)]"> / 100</span>
                  </p>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </Card>
  )
}

function PostureTrendChart({
  snap,
  trend,
  rangeDays,
}: {
  snap: PostureSnapshotResponse
  trend: PostureTrendResponse
  rangeDays: PostureRange
}) {
  const [hoverIdx, setHoverIdx] = React.useState<number | null>(null)
  const [boxRef, W] = useMeasuredWidth<HTMLDivElement>()
  const points = trend.points
  if (points.length < 2) {
    return (
      <Card className="rounded-md">
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
          Open findings by severity — last {RANGE_LABEL[rangeDays]}
        </h2>
        <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
          Not enough data to plot a trend yet.
        </p>
      </Card>
    )
  }

  // Rendered at the measured pixel width (viewBox 1:1) — no preserveAspectRatio
  // distortion; markers are true circles and axis text stays crisp.
  const H = 224
  const PAD_L = 40
  const PAD_R = 8
  const PAD_T = 8
  const PAD_B = 24
  const plotW = Math.max(W - PAD_L - PAD_R, 0)
  const plotH = H - PAD_T - PAD_B
  const xOf = (i: number) => PAD_L + (plotW * i) / (points.length - 1)

  // Build cumulative totals so each layer's top line sits above the previous.
  const cumulative: number[][] = points.map(() => [0, 0, 0, 0])
  STACK_ORDER.forEach((layer, idx) => {
    points.forEach((p, i) => {
      const previous = idx === 0 ? 0 : cumulative[i][idx - 1]
      cumulative[i][idx] = previous + p[layer]
    })
  })
  const maxTotal = Math.max(...points.map((p) => p.total), 1)
  const yOf = (value: number) => PAD_T + plotH - (value / maxTotal) * plotH

  function areaPath(layerIdx: number): string {
    const top = points
      .map((_, i) => `${i === 0 ? "M" : "L"}${xOf(i).toFixed(1)},${yOf(cumulative[i][layerIdx]).toFixed(1)}`)
      .join(" ")
    let bottom: string
    if (layerIdx === 0) {
      bottom = ` L${xOf(points.length - 1).toFixed(1)},${yOf(0).toFixed(1)} L${xOf(0).toFixed(1)},${yOf(0).toFixed(1)} Z`
    } else {
      // Reverse along the previous layer's top.
      const back = points
        .map((_, i) => {
          const idx = points.length - 1 - i
          return `L${xOf(idx).toFixed(1)},${yOf(cumulative[idx][layerIdx - 1]).toFixed(1)}`
        })
        .join(" ")
      bottom = ` ${back} Z`
    }
    return top + bottom
  }

  const gridSteps = [0.25, 0.5, 0.75, 1.0]

  function idxFromPointer(e: React.PointerEvent<HTMLDivElement>) {
    const rect = e.currentTarget.getBoundingClientRect()
    if (rect.width === 0) return
    const frac = Math.min(Math.max((e.clientX - rect.left) / rect.width, 0), 1)
    setHoverIdx(Math.round(frac * (points.length - 1)))
  }

  const hovered = hoverIdx !== null ? points[hoverIdx] : null
  const tooltipAlign =
    hoverIdx === null
      ? "-translate-x-1/2"
      : hoverIdx <= 2
        ? "translate-x-0"
        : hoverIdx >= points.length - 3
          ? "-translate-x-full"
          : "-translate-x-1/2"

  return (
    <Card className="rounded-md">
      <div className="flex items-center justify-between gap-3 mb-3">
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
          Open findings by severity — last {RANGE_LABEL[rangeDays]}
        </h2>
      </div>
      <div ref={boxRef} className="relative" style={{ height: H }}>
        {W > 0 && (
          <>
            <svg
              width="100%"
              height={H}
              viewBox={`0 0 ${W} ${H}`}
              className="block"
              role="img"
              aria-label={`Stacked-area chart of open findings by severity over the last ${RANGE_LABEL[rangeDays]}`}
            >
              <g stroke="var(--color-border)" strokeOpacity="0.5">
                {gridSteps.map((g) => (
                  <line key={g} x1={PAD_L} y1={yOf(maxTotal * g)} x2={W - PAD_R} y2={yOf(maxTotal * g)} />
                ))}
              </g>
              <g fontSize="10" fill="var(--color-text-secondary)">
                {gridSteps.map((g) => (
                  <text key={g} x="0" y={yOf(maxTotal * g) + 3.5}>
                    {Math.round(maxTotal * g).toLocaleString()}
                  </text>
                ))}
              </g>
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
                x1={xOf(points.length - 1)}
                y1={PAD_T}
                x2={xOf(points.length - 1)}
                y2={PAD_T + plotH}
                stroke="var(--color-accent)"
                strokeWidth="1"
                strokeDasharray="2 3"
                opacity="0.6"
              />
              {hoverIdx !== null && (
                <line
                  x1={xOf(hoverIdx)}
                  y1={PAD_T}
                  x2={xOf(hoverIdx)}
                  y2={PAD_T + plotH}
                  stroke="var(--color-text-secondary)"
                  strokeWidth="1"
                />
              )}
              <g fontSize="10" fill="var(--color-text-secondary)">
                <text x={PAD_L} y={H - 8}>{formatChartDate(points[0].date)}</text>
                <text x={PAD_L + plotW / 2} y={H - 8} textAnchor="middle">
                  {formatChartDate(points[Math.floor(points.length / 2)].date)}
                </text>
                <text x={PAD_L + plotW} y={H - 8} textAnchor="end" fill="var(--color-accent)">
                  Today
                </text>
              </g>
              {hoverIdx !== null && (
                <circle
                  cx={xOf(hoverIdx)}
                  cy={yOf(points[hoverIdx].total)}
                  r="3.5"
                  fill="var(--color-text-primary)"
                  stroke="var(--color-surface)"
                  strokeWidth="2"
                />
              )}
            </svg>
            <div
              className="absolute inset-y-0 cursor-crosshair"
              style={{ left: PAD_L, width: plotW }}
              onPointerMove={idxFromPointer}
              onPointerLeave={() => setHoverIdx(null)}
            />
            {hovered && hoverIdx !== null && (
              <div
                className={`pointer-events-none absolute top-1 z-10 ${tooltipAlign}`}
                style={{ left: xOf(hoverIdx) }}
              >
                <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 shadow-lg">
                  <p className="mb-1.5 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
                    {formatChartDate(hovered.date)}
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
          </>
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


interface TeamRowVM {
  key: string
  label: string
  bar: number
  barColor: string
  count: number
}

function TeamRiskPanel({ teams }: { teams: TeamPostureItem[] | null }) {
  let rows: TeamRowVM[] | null = null
  let emptyMessage = ""

  if (teams === null) {
    rows = null
  } else if (teams.length === 0) {
    rows = []
    emptyMessage = "Team data not configured."
  } else {
    const slice = teams.slice(0, 6)
    // Bar length tracks the same quantity as the printed number (critical + high).
    const maxCount = Math.max(...slice.map((t) => t.counts.critical + t.counts.high), 1)
    rows = slice.map((team) => {
      const count = team.counts.critical + team.counts.high
      return {
        key: team.team_id,
        label: team.team_name,
        bar: count > 0 ? Math.max(count / maxCount, 0.08) : 0,
        barColor: getRatingTokens(team.risk_score.rating).color,
        count,
      }
    })
  }

  return (
    <Card className="rounded-md">
      <div className="flex items-center justify-between gap-3 mb-4">
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
          Risk by team
        </h2>
        <span className="text-2xs font-medium uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
          Critical + high
        </span>
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
  // While loading (frameworks === null) show a few skeletons; otherwise render
  // exactly the frameworks that exist — no fake "No framework" padding cards.
  const slots: (ComplianceFramework | undefined)[] =
    frameworks === null ? [undefined, undefined, undefined] : frameworks.slice(0, 4)

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
      <h2 className="text-base font-semibold text-[var(--color-text-primary)] mb-4">
        Compliance posture
      </h2>
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
          const controls = summaries[fw.id]
          if (!controls) {
            return (
              <Card key={fw.id} padding="none" className="rounded-md px-5 py-4">
                <p className="text-xs font-semibold text-[var(--color-text-primary)]">{fw.label}</p>
                <Skeleton className="mt-3 h-4 w-16" />
                <Skeleton className="mt-2 h-3 w-24" />
              </Card>
            )
          }
          const passing = controls.filter((c) => c.finding_count === 0).length
          const total = controls.length
          return (
            <Card key={fw.id} padding="none" className="rounded-md px-5 py-4">
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


export interface PostureSummaryTabProps {
  snap: PostureSnapshotResponse
  trend: PostureTrendResponse
  teams: TeamPostureItem[] | null
  frameworks: ComplianceFramework[] | null
  complianceSummaries: Record<string, ControlSummaryItem[]>
  slaSummary: SlaBreachSummary | null
  rangeDays: PostureRange
  onRangeChange: (days: PostureRange) => void
}

export function PostureSummaryTab({
  snap,
  trend,
  teams,
  frameworks,
  complianceSummaries,
  slaSummary,
  rangeDays,
  onRangeChange,
}: PostureSummaryTabProps) {
  return (
    <div className="px-6 py-5 space-y-5">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm text-[var(--color-text-secondary)]">
          Trends over the last {RANGE_LABEL[rangeDays]}
        </p>
        <SegmentedControl
          ariaLabel="Trend time range"
          size="xs"
          value={String(rangeDays)}
          onChange={(id) => onRangeChange(Number(id) as PostureRange)}
          options={[
            { id: "30", label: "30D" },
            { id: "90", label: "90D" },
            { id: "365", label: "1Y" },
          ]}
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <RiskScoreHero snap={snap} trend={trend} rangeDays={rangeDays} />
        <KpiGrid snap={snap} trend={trend} slaSummary={slaSummary} />
      </div>

      <AttentionPanel snap={snap} teams={teams} />

      <div className="grid gap-5 lg:grid-cols-2">
        <RiskTrendChart
          trend={trend}
          rangeDays={rangeDays}
          color={getRatingTokens(snap.riskScore.rating).color}
        />
        <PostureTrendChart snap={snap} trend={trend} rangeDays={rangeDays} />
      </div>

      <div className="grid gap-5 lg:grid-cols-3">
        <SeverityDonut snap={snap} />
        <TeamRiskPanel teams={teams} />
        <TopReposPanel repos={snap.topRepositories} />
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <RepositoryCoveragePanel snap={snap} />
        {snap.ageBuckets.length > 0 && <AgeBucketsPanel buckets={snap.ageBuckets} />}
      </div>

      <ComplianceSnapshot frameworks={frameworks} summaries={complianceSummaries} />

      <p className="text-xs text-[var(--color-text-tertiary)]">
        Covers scanned source code only — runtime is not directly observed.
      </p>
    </div>
  )
}
