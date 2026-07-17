"use client"

import * as React from "react"
import Link from "next/link"

import type {
  PostureSnapshotResponse,
  PostureTrendResponse,
  TeamPostureItem,
  ExploitabilitySummary,
  SlaPostureSummary,
} from "@/lib/client/posture-api"
import type { ComplianceFramework, ControlSummaryItem } from "@/lib/client/compliance-api"
import type { SlaBreachSummary } from "@/lib/client/sla-api"
import { SegmentedControl } from "@/components/ui/SegmentedControl"
import { Card } from "@/components/ui/Card"
import { Button } from "@/components/ui/Button"
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
  unrated: "var(--color-text-tertiary)",
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
      ? "text-[var(--color-severity-critical-text)]"
      : "text-[var(--color-status-ok-text)]"
  } else if (direction === "down") {
    arrow = "▼"
    color = upIsBad
      ? "text-[var(--color-status-ok-text)]"
      : "text-[var(--color-severity-critical-text)]"
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
  onSwitchToTriage,
}: {
  snap: PostureSnapshotResponse
  trend: PostureTrendResponse
  rangeDays: PostureRange
  onSwitchToTriage?: () => void
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
        ? "text-[var(--color-status-ok-text)]"
        : "text-[var(--color-severity-high-text)]"
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
    <div className={`rounded-md border ${border} ${bg} overflow-hidden`}>
      <div className="px-6 pt-5 pb-4">
        <div className="flex items-center gap-1.5">
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
            Risk score
          </h2>
          <span className="group relative inline-flex">
            <button
              type="button"
              aria-label="How the risk score is computed"
              className="inline-flex h-4 w-4 items-center justify-center rounded-full text-[var(--color-text-tertiary)] transition-colors hover:text-[var(--color-text-secondary)] focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
            >
              <svg width="13" height="13" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9 9a1 1 0 012 0v4a1 1 0 11-2 0V9zm1-4a1 1 0 100 2 1 1 0 000-2z" clipRule="evenodd" />
              </svg>
            </button>
            <span
              role="tooltip"
              className="pointer-events-none absolute left-0 top-full z-20 mt-1.5 w-72 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 text-xs leading-relaxed text-[var(--color-text-secondary)] opacity-0 shadow-md transition-opacity duration-150 group-hover:opacity-100 group-focus-within:opacity-100"
            >
              Weighs every open finding by severity, then by exploitability — findings on CISA&rsquo;s KEV list (actively exploited) and reachable high-severity ones count for more. The total maps to 0&ndash;100 on a curve that keeps rising as the backlog grows but never pins at 100. Lower is better.
            </span>
          </span>
        </div>
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

        {onSwitchToTriage && (
          <Button
            variant="link"
            size="sm"
            onClick={onSwitchToTriage}
            className="mt-3 inline-flex items-center gap-1 font-medium text-[var(--color-accent)]"
            aria-label="View what drives the risk score in the Triage tab"
          >
            What drives this?
            <svg
              viewBox="0 0 16 16"
              className="h-3 w-3"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.75"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M6 4l4 4-4 4" />
            </svg>
          </Button>
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
      className={`h-full rounded-md px-5 py-3 ${href ? "transition-colors hover:border-[var(--color-accent)]/40" : ""}`}
    >
      <div className="flex items-start justify-between gap-2">
        <p className="text-2xs font-mono font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
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
  exploitability,
  slaPosture,
}: {
  snap: PostureSnapshotResponse
  trend: PostureTrendResponse
  slaSummary: SlaBreachSummary | null
  exploitability?: ExploitabilitySummary | null
  slaPosture?: SlaPostureSummary | null
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
        href={findingsHref({ severity: "critical", state: "open" })}
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
              <strong className="font-semibold text-[var(--color-severity-critical-text)]">
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

      <KpiCard
        label="KEV-exposed"
        value={
          exploitability
            ? exploitability.kevCount.toLocaleString()
            : "—"
        }
        detail={
          exploitability == null
            ? "Loading exploitability data"
            : exploitability.kevCount > 0
              ? "Known exploited vulnerabilities"
              : "None in known exploited catalog"
        }
        spark={null}
        sparkStroke="var(--color-severity-critical)"
        delta={null}
        href={findingsHref({ kev: true, state: "open" })}
      />

      <KpiCard
        label="SLA breached"
        value={
          slaPosture != null
            ? slaPosture.totalBreached.toLocaleString()
            : "—"
        }
        detail={
          slaPosture == null
            ? "Loading SLA data"
            : slaPosture.totalBreached > 0
              ? `Oldest breach ${slaPosture.maxBreachAgeDays}d ago`
              : "All findings within SLA"
        }
        spark={null}
        sparkStroke="var(--color-severity-high)"
        delta={null}
      />
    </div>
  )
}


type AttentionTone = "critical" | "high" | "medium"

const ATTENTION_TONE_BG: Record<AttentionTone, string> = {
  critical: "bg-[var(--color-severity-critical)]/10 text-[var(--color-severity-critical-text)]",
  high: "bg-[var(--color-severity-high)]/10 text-[var(--color-severity-high-text)]",
  medium: "bg-[var(--color-severity-medium)]/10 text-[var(--color-severity-medium-text)]",
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
  exploitability,
  slaPosture,
}: {
  snap: PostureSnapshotResponse
  teams: TeamPostureItem[] | null
  exploitability?: ExploitabilitySummary | null
  slaPosture?: SlaPostureSummary | null
}) {
  // snap is always present here; teams and exploitability load in parallel and
  // may still be null. Build snap-derived rows immediately.
  const rows: AttentionRow[] = []

  const topCritical = snap.topRepositories.find((r) => r.critical > 0)
  if (topCritical) {
    rows.push({
      tone: "critical",
      icon: "shield",
      title: `${topCritical.critical} critical finding${topCritical.critical !== 1 ? "s" : ""} in ${topCritical.name}`,
      sub: "Requires immediate review",
      href: findingsHref({ repo: topCritical.name, severity: "critical", state: "open" }),
    })
  }

  // KEV exposure — highest priority exploitability signal; link resolves to
  // /findings?kev=true&state=open which matches the count shown.
  if (exploitability && exploitability.kevCount > 0) {
    rows.push({
      tone: "critical",
      icon: "shield",
      title: `${exploitability.kevCount.toLocaleString()} finding${exploitability.kevCount !== 1 ? "s" : ""} in known exploited catalog`,
      sub: "CVE actively exploited in the wild",
      href: findingsHref({ kev: true, state: "open" }),
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

  // SLA breach summary — show oldest breach age when there are breaches.
  if (slaPosture && slaPosture.totalBreached > 0) {
    rows.push({
      tone: "high",
      icon: "warning",
      title: `${slaPosture.totalBreached.toLocaleString()} finding${slaPosture.totalBreached !== 1 ? "s" : ""} past SLA`,
      sub: slaPosture.maxBreachAgeDays > 0
        ? `Oldest breach ${slaPosture.maxBreachAgeDays}d ago`
        : "Review and resolve breached findings",
    })
  }

  // Age bucket — 90+ day findings
  const overNinety = snap.ageBuckets[3]?.count ?? 0
  if (overNinety > 0) {
    rows.push({
      tone: "high",
      icon: "warning",
      title: `${overNinety.toLocaleString()} findings open over 90 days`,
      sub: "Review aging backlog",
      href: findingsHref({ age: "90d", state: "open" }),
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
  const plotW = Math.max(W - PAD_L - PAD_R, 0)
  const plotH = H - PAD_T - PAD_B

  // Auto-range the y-axis to the data so the trend stays legible even when the
  // score sits high and stable — a fixed 0–100 axis crushes the line against
  // the ceiling and wastes the whole plot. A minimum span keeps day-to-day
  // noise from reading as dramatic swings, and the axis is labelled with the
  // true values so magnitude context is never lost.
  const scores = points.map((p) => p.risk_score)
  const dataMin = Math.min(...scores)
  const dataMax = Math.max(...scores)
  const MIN_SPAN = 20
  const rawSpan = Math.max(dataMax - dataMin, MIN_SPAN)
  const yLo = Math.max(0, Math.floor((dataMin - rawSpan * 0.15) / 5) * 5)
  const yHi = Math.min(100, Math.ceil((dataMax + rawSpan * 0.15) / 5) * 5)
  const ySpan = Math.max(yHi - yLo, 1)
  const xOf = (i: number) => PAD_L + (plotW * i) / (points.length - 1)
  const yOf = (v: number) => PAD_T + plotH - ((v - yLo) / ySpan) * plotH

  const linePath = points
    .map((p, i) => `${i === 0 ? "M" : "L"}${xOf(i).toFixed(1)},${yOf(p.risk_score).toFixed(1)}`)
    .join(" ")
  const areaPath = `${linePath} L${xOf(points.length - 1).toFixed(1)},${yOf(yLo).toFixed(1)} L${xOf(0).toFixed(1)},${yOf(yLo).toFixed(1)} Z`
  // Gridlines across the auto-ranged band, labelled with true score values.
  const gridVals = [0, 0.25, 0.5, 0.75, 1].map((f) => Math.round(yLo + f * ySpan))

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

  // Period velocity — how much has the score moved from start to end of range?
  // Meaningful only when we have ≥ 2 distinct points.
  const periodRiskDelta = points[points.length - 1].risk_score - points[0].risk_score
  const periodVelocityNode: React.ReactNode = (() => {
    const abs = Math.abs(periodRiskDelta)
    // Treat ≤1 pt change as stable — rounding noise from the scoring formula.
    if (abs <= 1)
      return (
        <span className="text-2xs font-medium tabular-nums text-[var(--color-text-tertiary)]">
          — stable over period
        </span>
      )
    const isImproving = periodRiskDelta < 0
    const arrow = isImproving ? "▼" : "▲"
    const tone = isImproving
      ? "text-[var(--color-status-ok-text)]"
      : "text-[var(--color-severity-high-text)]"
    const verb = isImproving ? "improving" : "worsening"
    return (
      <span className={`inline-flex items-center gap-1 text-2xs font-semibold tabular-nums ${tone}`}>
        <span aria-hidden="true">{arrow}</span>
        <span>{abs} pts</span>
        <span className="font-normal text-[var(--color-text-tertiary)]">{verb} over period</span>
      </span>
    )
  })()

  return (
    <Card className="rounded-md">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
          Risk score over time
        </h2>
        <div className="flex flex-wrap items-center gap-3">
          {periodVelocityNode}
          <span className="text-2xs font-medium uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
            Last {RANGE_LABEL[rangeDays]} · lower is better
          </span>
        </div>
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
                  <stop offset="0%" stopColor={color} stopOpacity="0.32" />
                  <stop offset="55%" stopColor={color} stopOpacity="0.1" />
                  <stop offset="100%" stopColor={color} stopOpacity="0" />
                </linearGradient>
                <filter id={`${gradId}-glow`} x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>
              <g stroke="var(--color-border)" strokeOpacity="0.4">
                {gridVals.map((v, gi) => (
                  <line key={gi} x1={PAD_L} y1={yOf(v)} x2={W - PAD_R} y2={yOf(v)} />
                ))}
              </g>
              <g fontSize="10" fill="var(--color-text-secondary)">
                {gridVals.map((v, gi) => (
                  <text key={gi} x="0" y={yOf(v) + 3.5}>
                    {v}
                  </text>
                ))}
              </g>
              <path d={areaPath} fill={`url(#${gradId})`} className="chart-rise" />
              {/* Soft under-glow behind the primary stroke for depth. */}
              <path
                d={linePath}
                fill="none"
                stroke={color}
                strokeOpacity="0.35"
                strokeWidth="4"
                strokeLinecap="round"
                strokeLinejoin="round"
                filter={`url(#${gradId}-glow)`}
                pathLength={1}
                className="chart-draw"
              />
              <path
                d={linePath}
                fill="none"
                stroke={color}
                strokeWidth="2.25"
                strokeLinecap="round"
                strokeLinejoin="round"
                pathLength={1}
                className="chart-draw"
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
              {/* Period-start reference line — shows where the score began. */}
              <line
                x1={PAD_L}
                y1={yOf(points[0].risk_score)}
                x2={W - PAD_R}
                y2={yOf(points[0].risk_score)}
                stroke="var(--color-text-secondary)"
                strokeOpacity="0.25"
                strokeWidth="1"
                strokeDasharray="3 4"
              />
              <text
                x={PAD_L + 2}
                y={yOf(points[0].risk_score) - 3}
                fontSize="9"
                fill="var(--color-text-tertiary)"
              >
                start
              </text>

              {/* Current-value + hover markers — true round circles at 1:1. */}
              <circle
                cx={xOf(points.length - 1)}
                cy={yOf(points[points.length - 1].risk_score)}
                r="7"
                fill={color}
                fillOpacity="0.15"
                className="chart-fade"
                style={{ animationDelay: "700ms" }}
              />
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
                  {(hovered.critical > 0 || hovered.high > 0 || hovered.medium > 0 || hovered.low > 0) && (
                    <div className="mt-1.5 flex items-center gap-2">
                      {(
                        [
                          { key: "critical", label: "C", color: "var(--color-severity-critical-text)" },
                          { key: "high",     label: "H", color: "var(--color-severity-high-text)" },
                          { key: "medium",   label: "M", color: "var(--color-severity-medium-text)" },
                          { key: "low",      label: "L", color: "var(--color-severity-low-text)" },
                        ] as const
                      )
                        .filter((s) => hovered[s.key] > 0)
                        .map((s) => (
                          <span key={s.key} className="flex items-center gap-0.5 text-2xs tabular-nums">
                            <span
                              className="inline-block h-1.5 w-1.5 rounded-full shrink-0"
                              style={{ background: s.color }}
                            />
                            <span className="text-[var(--color-text-secondary)]">
                              {hovered[s.key].toLocaleString()}
                            </span>
                          </span>
                        ))}
                    </div>
                  )}
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
  const chartId = `stacked-${React.useId().replace(/:/g, "")}`
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

  const netFindingsDelta = points[points.length - 1].total - points[0].total
  const netFindingsNode: React.ReactNode = (() => {
    if (netFindingsDelta === 0)
      return (
        <span className="text-2xs font-medium tabular-nums text-[var(--color-text-tertiary)]">
          — unchanged over period
        </span>
      )
    const isReduced = netFindingsDelta < 0
    const abs = Math.abs(netFindingsDelta)
    const arrow = isReduced ? "▼" : "▲"
    const tone = isReduced
      ? "text-[var(--color-status-ok-text)]"
      : "text-[var(--color-severity-high-text)]"
    return (
      <span className={`inline-flex items-center gap-1 text-2xs font-semibold tabular-nums ${tone}`}>
        <span aria-hidden="true">{arrow}</span>
        <span>{abs.toLocaleString()} open</span>
        <span className="font-normal text-[var(--color-text-tertiary)]">net over period</span>
      </span>
    )
  })()

  return (
    <Card className="rounded-md">
      <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
          Open findings by severity — last {RANGE_LABEL[rangeDays]}
        </h2>
        {netFindingsNode}
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
              <defs>
                {STACK_ORDER.map((layer) => (
                  <linearGradient
                    key={layer}
                    id={`${chartId}-${layer}`}
                    x1="0" y1={PAD_T} x2="0" y2={PAD_T + plotH}
                    gradientUnits="userSpaceOnUse"
                  >
                    <stop offset="0%" stopColor={STACK_FILL[layer].color} stopOpacity={STACK_FILL[layer].opacity} />
                    <stop offset="100%" stopColor={STACK_FILL[layer].color} stopOpacity={STACK_FILL[layer].opacity * 0.35} />
                  </linearGradient>
                ))}
              </defs>
              <g stroke="var(--color-border)" strokeOpacity="0.35">
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
                <React.Fragment key={layer}>
                  <path
                    d={areaPath(idx)}
                    fill={`url(#${chartId}-${layer})`}
                    className="chart-rise"
                    style={{ animationDelay: `${idx * 90}ms` }}
                  />
                  <path
                    d={points.map((_, i) => `${i === 0 ? "M" : "L"}${xOf(i).toFixed(1)},${yOf(cumulative[i][idx]).toFixed(1)}`).join(" ")}
                    fill="none"
                    stroke={STACK_FILL[layer].color}
                    strokeWidth={idx === STACK_ORDER.length - 1 ? 1.5 : 0.75}
                    strokeOpacity={STACK_FILL[layer].opacity + 0.1}
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    pathLength={1}
                    className="chart-draw"
                    style={{ animationDelay: `${idx * 90}ms` }}
                  />
                </React.Fragment>
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
        {(["critical", "high", "medium", "low", "unrated"] as const)
          .map((sev) => [sev, sev === "unrated" ? snap.counts.unknown : snap.counts[sev]] as const)
          .filter(([, n]) => n > 0)
          .map(([sev, n]) => (
          <span key={sev} className="inline-flex items-center gap-1.5">
            <span
              className="h-2.5 w-2.5 rounded-sm"
              style={{ background: SEV_VARS[sev] }}
              aria-hidden="true"
            />
            <span className="capitalize">{sev}</span>
            <span className="font-semibold tabular-nums text-[var(--color-text-primary)]">
              {n.toLocaleString()}
            </span>
          </span>
        ))}
      </div>
    </Card>
  )
}


// ── Discovery Velocity Chart ────────────────────────────────────────────────

/**
 * Dual-bar chart showing findings introduced vs resolved per day.
 * "Resolved" is derived: resolved[i] = max(0, new[i] − netChange[i])
 * where netChange = open[i] − open[i−1].
 */
function DiscoveryVelocityChart({
  trend,
  rangeDays,
}: {
  trend: PostureTrendResponse
  rangeDays: PostureRange
}) {
  const [hoverIdx, setHoverIdx] = React.useState<number | null>(null)
  const [boxRef, W] = useMeasuredWidth<HTMLDivElement>()
  const barId = `vel-${React.useId().replace(/:/g, "")}`
  const points = trend.points

  const derived = React.useMemo(() => points.map((p, i) => {
    const introduced = p.new_findings
    const netChange = i === 0 ? 0 : p.total - points[i - 1].total
    const resolved = Math.max(0, introduced - netChange)
    return { introduced, resolved }
  }), [points])

  const hasData = derived.some(d => d.introduced > 0)

  if (points.length < 2) return null

  if (!hasData) {
    return (
      <Card className="rounded-md">
        <div className="mb-1 flex items-center gap-2">
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
            Discovery velocity
          </h2>
          <span className="rounded-full bg-[var(--color-surface-muted)] px-2 py-0.5 text-2xs font-medium text-[var(--color-text-secondary)] uppercase tracking-[0.14em]">
            last {RANGE_LABEL[rangeDays]}
          </span>
        </div>
        <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
          Velocity data will populate after the next nightly snapshot run.
        </p>
      </Card>
    )
  }

  const periodIntroduced = derived.reduce((s, d) => s + d.introduced, 0)
  const periodResolved = derived.reduce((s, d) => s + d.resolved, 0)
  const periodNet = periodIntroduced - periodResolved

  const H = 148
  const PAD_L = 38
  const PAD_R = 8
  const PAD_T = 8
  const PAD_B = 22
  const plotW = Math.max(W - PAD_L - PAD_R, 0)
  const plotH = H - PAD_T - PAD_B
  const maxVal = Math.max(...derived.map(d => Math.max(d.introduced, d.resolved)), 1)
  const yOf = (v: number) => PAD_T + plotH - (v / maxVal) * plotH

  const groupW = plotW / Math.max(points.length, 1)
  const barGap = 1.5
  const barW = Math.max(1, (groupW * 0.82) / 2 - barGap / 2)
  const xOfGroup = (i: number) => PAD_L + i * groupW + groupW * 0.09

  function idxFromPointer(e: React.PointerEvent<HTMLDivElement>) {
    const rect = e.currentTarget.getBoundingClientRect()
    if (rect.width === 0) return
    const frac = Math.min(Math.max((e.clientX - rect.left - PAD_L) / plotW, 0), 1)
    setHoverIdx(Math.round(frac * (points.length - 1)))
  }

  const gridSteps = [0.25, 0.5, 0.75, 1.0]
  const hov = hoverIdx !== null ? { ...derived[hoverIdx], date: points[hoverIdx].date, idx: hoverIdx } : null

  return (
    <Card className="rounded-md">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
            Discovery velocity
          </h2>
          <span className="rounded-full bg-[var(--color-surface-muted)] px-2 py-0.5 text-2xs font-medium text-[var(--color-text-secondary)] uppercase tracking-[0.14em]">
            last {RANGE_LABEL[rangeDays]}
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-2xs tabular-nums">
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-2 w-2 rounded-sm shrink-0" style={{ background: "var(--color-severity-high)" }} />
            <span className="text-[var(--color-text-secondary)]">Introduced</span>
            <span className="font-semibold" style={{ color: "var(--color-severity-high-text)" }}>
              {periodIntroduced.toLocaleString()}
            </span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-2 w-2 rounded-sm shrink-0" style={{ background: "var(--color-status-ok)" }} />
            <span className="text-[var(--color-text-secondary)]">Resolved</span>
            <span className="font-semibold" style={{ color: "var(--color-status-ok-text)" }}>
              {periodResolved.toLocaleString()}
            </span>
          </span>
          {periodNet !== 0 && (
            <span
              className="font-semibold"
              style={{ color: periodNet > 0 ? "var(--color-severity-high-text)" : "var(--color-status-ok-text)" }}
            >
              {periodNet > 0 ? "▲" : "▼"} {Math.abs(periodNet).toLocaleString()} net
            </span>
          )}
          {periodNet === 0 && periodIntroduced > 0 && (
            <span className="text-2xs font-medium" style={{ color: "var(--color-status-ok-text)" }}>
              — net zero
            </span>
          )}
        </div>
      </div>

      <div ref={boxRef} className="relative select-none" style={{ height: H }}>
        {W > 0 && (
          <svg
            width="100%"
            height={H}
            viewBox={`0 0 ${W} ${H}`}
            className="block"
            role="img"
            aria-label="Findings introduced vs resolved per day"
          >
            <defs>
              <linearGradient id={`${barId}-intro`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--color-severity-high)" stopOpacity="0.9" />
                <stop offset="100%" stopColor="var(--color-severity-high)" stopOpacity="0.35" />
              </linearGradient>
              <linearGradient id={`${barId}-resolved`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--color-status-ok)" stopOpacity="0.85" />
                <stop offset="100%" stopColor="var(--color-status-ok)" stopOpacity="0.3" />
              </linearGradient>
            </defs>

            {/* Subtle grid */}
            <g stroke="var(--color-border)" strokeOpacity="0.3">
              {gridSteps.map((g) => (
                <line key={g} x1={PAD_L} y1={yOf(maxVal * g)} x2={W - PAD_R} y2={yOf(maxVal * g)} />
              ))}
            </g>
            <g fontSize="10" fill="var(--color-text-tertiary)">
              {gridSteps.map((g) => (
                <text key={g} x="0" y={yOf(maxVal * g) + 3.5} textAnchor="start">
                  {Math.round(maxVal * g)}
                </text>
              ))}
            </g>

            {/* Bars */}
            {derived.map((d, i) => {
              const gx = xOfGroup(i)
              const introH = Math.max(0, (d.introduced / maxVal) * plotH)
              const resolvedH = Math.max(0, (d.resolved / maxVal) * plotH)
              const isHov = hoverIdx === i
              const dimmed = hoverIdx !== null && !isHov
              const delay = `${Math.min(i * 12, 360)}ms`
              return (
                <g key={i} opacity={dimmed ? 0.35 : 1} style={{ transition: "opacity 80ms" }}>
                  {introH > 0 && (
                    <rect
                      x={gx}
                      y={yOf(d.introduced)}
                      width={barW}
                      height={introH}
                      fill={`url(#${barId}-intro)`}
                      rx="1.5"
                      className="chart-grow"
                      style={{ animationDelay: delay }}
                    />
                  )}
                  {resolvedH > 0 && (
                    <rect
                      x={gx + barW + barGap}
                      y={yOf(d.resolved)}
                      width={barW}
                      height={resolvedH}
                      fill={`url(#${barId}-resolved)`}
                      rx="1.5"
                      className="chart-grow"
                      style={{ animationDelay: delay }}
                    />
                  )}
                </g>
              )
            })}

            {/* Date axis */}
            <g fontSize="10" fill="var(--color-text-secondary)">
              <text x={PAD_L} y={H - 8}>{formatChartDate(points[0].date)}</text>
              <text x={PAD_L + plotW / 2} y={H - 8} textAnchor="middle">
                {formatChartDate(points[Math.floor(points.length / 2)].date)}
              </text>
              <text x={PAD_L + plotW} y={H - 8} textAnchor="end" fill="var(--color-accent)">
                Today
              </text>
            </g>
          </svg>
        )}

        {/* Hover hit area */}
        <div
          className="absolute inset-0 cursor-crosshair"
          onPointerMove={idxFromPointer}
          onPointerLeave={() => setHoverIdx(null)}
        />

        {/* Tooltip */}
        {hov && (
          <div
            className="pointer-events-none absolute top-1 z-10 flex min-w-[120px] flex-col gap-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-2.5 py-1.5 text-2xs shadow-md"
            style={{
              left: `${PAD_L + (hov.idx + 0.5) * groupW}px`,
              transform: hov.idx < points.length / 2
                ? "translateX(6px)"
                : "translateX(calc(-100% - 6px))",
            }}
          >
            <span className="font-medium text-[var(--color-text-secondary)]">
              {formatChartDate(hov.date)}
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: "var(--color-severity-high)" }} />
              <span className="text-[var(--color-text-secondary)]">Introduced</span>
              <span className="ml-auto pl-2 font-semibold tabular-nums" style={{ color: "var(--color-severity-high-text)" }}>
                {hov.introduced.toLocaleString()}
              </span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: "var(--color-status-ok)" }} />
              <span className="text-[var(--color-text-secondary)]">Resolved</span>
              <span className="ml-auto pl-2 font-semibold tabular-nums" style={{ color: "var(--color-status-ok-text)" }}>
                {hov.resolved.toLocaleString()}
              </span>
            </span>
          </div>
        )}
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
        <span className="inline-flex items-center rounded-full px-2 py-0.5 text-2xs font-semibold bg-[var(--color-status-ok)]/10 text-[var(--color-status-ok-text)]">
          On track
        </span>
      )
    }
    if (pct >= 0.8) {
      return (
        <span className="inline-flex items-center rounded-full px-2 py-0.5 text-2xs font-semibold bg-[var(--color-severity-medium)]/15 text-[var(--color-severity-medium-text)]">
          Partial
        </span>
      )
    }
    return (
      <span className="inline-flex items-center rounded-full px-2 py-0.5 text-2xs font-semibold bg-[var(--color-severity-critical)]/15 text-[var(--color-severity-critical-text)]">
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


// ── Open backlog level chart ────────────────────────────────────────────────

/**
 * Actual count of open findings per day — the standing backlog level. A rising
 * line means findings are accumulating faster than they're cleared; a falling
 * line means the team is burning the backlog down. Plotting the level directly
 * (rather than two near-coincident cumulative curves) keeps the movement that
 * matters legible even when introduced and resolved run close together.
 */
function BacklogFlowChart({
  trend,
  rangeDays,
}: {
  trend: PostureTrendResponse
  rangeDays: PostureRange
}) {
  const [hoverIdx, setHoverIdx] = React.useState<number | null>(null)
  const [boxRef, W] = useMeasuredWidth<HTMLDivElement>()
  const gradId = `backlog-${React.useId().replace(/:/g, "")}`
  const points = trend.points

  const totals = points.map((p) => p.total)
  const hasData = totals.some((t) => t > 0)
  if (points.length < 2 || !hasData) return null

  const H = 200
  const PAD_L = 34
  const PAD_R = 10
  const PAD_T = 10
  const PAD_B = 24
  const plotW = Math.max(W - PAD_L - PAD_R, 0)
  const plotH = H - PAD_T - PAD_B

  // Auto-range so the trajectory is legible — a large stable backlog would sit
  // flat against a 0-anchored ceiling. Minimum span avoids exaggerating noise;
  // labels carry the true counts so magnitude context is kept.
  const dataMin = Math.min(...totals)
  const dataMax = Math.max(...totals)
  const MIN_SPAN = 10
  const rawSpan = Math.max(dataMax - dataMin, MIN_SPAN)
  const yLo = Math.max(0, Math.floor((dataMin - rawSpan * 0.15) / 5) * 5)
  const yHi = Math.ceil((dataMax + rawSpan * 0.15) / 5) * 5
  const ySpan = Math.max(yHi - yLo, 1)
  const xOf = (i: number) => PAD_L + (plotW * i) / (points.length - 1)
  const yOf = (v: number) => PAD_T + plotH - ((v - yLo) / ySpan) * plotH

  // Direction over the window drives the colour and the headline verb.
  const net = totals[totals.length - 1] - totals[0]
  const grew = net > 0
  const flat = Math.abs(net) <= 1
  const tone = flat
    ? "var(--color-text-tertiary)"
    : grew ? "var(--color-severity-high)" : "var(--color-status-ok)"
  const toneText = flat
    ? "var(--color-text-tertiary)"
    : grew ? "var(--color-severity-high-text)" : "var(--color-status-ok-text)"

  const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"}${xOf(i).toFixed(1)},${yOf(p.total).toFixed(1)}`).join(" ")
  const areaPath = `${linePath} L${xOf(points.length - 1).toFixed(1)},${yOf(yLo).toFixed(1)} L${xOf(0).toFixed(1)},${yOf(yLo).toFixed(1)} Z`
  const gridVals = [0, 0.25, 0.5, 0.75, 1].map((f) => Math.round(yLo + f * ySpan))

  function idxFromPointer(e: React.PointerEvent<HTMLDivElement>) {
    const rect = e.currentTarget.getBoundingClientRect()
    if (rect.width === 0) return
    const frac = Math.min(Math.max((e.clientX - rect.left - PAD_L) / plotW, 0), 1)
    setHoverIdx(Math.round(frac * (points.length - 1)))
  }

  const hov = hoverIdx !== null
    ? { total: points[hoverIdx].total, date: points[hoverIdx].date, delta: points[hoverIdx].total - totals[0], idx: hoverIdx }
    : null

  return (
    <Card className="rounded-md">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
            Open backlog over time
          </h2>
          <span className="rounded-full bg-[var(--color-surface-muted)] px-2 py-0.5 text-2xs font-medium uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
            last {RANGE_LABEL[rangeDays]}
          </span>
        </div>
        <span className="text-2xs font-semibold tabular-nums" style={{ color: toneText }}>
          {flat ? "— flat over period" : grew
            ? `▲ ${net.toLocaleString()} added over period`
            : `▼ ${Math.abs(net).toLocaleString()} cleared over period`}
        </span>
      </div>

      <div ref={boxRef} className="relative select-none" style={{ height: H }}>
        {W > 0 && (
          <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} className="block" role="img"
            aria-label="Open findings backlog level over the selected window">
            <defs>
              <linearGradient id={`${gradId}-fill`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={tone} stopOpacity="0.26" />
                <stop offset="100%" stopColor={tone} stopOpacity="0.03" />
              </linearGradient>
            </defs>
            <g stroke="var(--color-border)" strokeOpacity="0.35">
              {gridVals.map((v, gi) => (
                <line key={gi} x1={PAD_L} y1={yOf(v)} x2={W - PAD_R} y2={yOf(v)} />
              ))}
            </g>
            <g fontSize="10" fill="var(--color-text-tertiary)">
              {gridVals.map((v, gi) => (
                <text key={gi} x="0" y={yOf(v) + 3.5}>{v.toLocaleString()}</text>
              ))}
            </g>
            {/* Faint reference at the window-start level so growth reads at a glance. */}
            <line x1={PAD_L} y1={yOf(totals[0])} x2={W - PAD_R} y2={yOf(totals[0])}
              stroke="var(--color-text-secondary)" strokeOpacity="0.25" strokeWidth="1" strokeDasharray="3 4" />
            <path d={areaPath} fill={`url(#${gradId}-fill)`} className="chart-rise" />
            <path d={linePath} fill="none" stroke={tone} strokeWidth="2.25" strokeLinecap="round" strokeLinejoin="round" pathLength={1} className="chart-draw" />
            {hov && (
              <>
                <line x1={xOf(hov.idx)} y1={PAD_T} x2={xOf(hov.idx)} y2={PAD_T + plotH} stroke="var(--color-text-secondary)" strokeOpacity="0.3" strokeDasharray="3 3" />
                <circle cx={xOf(hov.idx)} cy={yOf(hov.total)} r="3.5" fill={tone} stroke="var(--color-surface)" strokeWidth="2" />
              </>
            )}
            <g fontSize="10" fill="var(--color-text-secondary)">
              <text x={PAD_L} y={H - 8}>{formatChartDate(points[0].date)}</text>
              <text x={PAD_L + plotW} y={H - 8} textAnchor="end" fill="var(--color-accent)">Today</text>
            </g>
          </svg>
        )}
        <div className="absolute inset-0 cursor-crosshair" onPointerMove={idxFromPointer} onPointerLeave={() => setHoverIdx(null)} />
        {hov && (
          <div className="pointer-events-none absolute top-1 z-10 flex min-w-[130px] flex-col gap-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-2.5 py-1.5 text-2xs shadow-md"
            style={{ left: `${xOf(hov.idx)}px`, transform: hov.idx < points.length / 2 ? "translateX(6px)" : "translateX(calc(-100% - 6px))" }}>
            <span className="font-medium text-[var(--color-text-secondary)]">{formatChartDate(hov.date)}</span>
            <span className="flex items-center gap-1.5">
              <span className="text-[var(--color-text-secondary)]">Open</span>
              <span className="ml-auto pl-2 font-semibold tabular-nums text-[var(--color-text-primary)]">{hov.total.toLocaleString()}</span>
            </span>
            <span className="flex items-center gap-1.5 border-t border-[var(--color-border)] pt-1">
              <span className="text-[var(--color-text-secondary)]">vs start</span>
              <span className="ml-auto pl-2 font-semibold tabular-nums"
                style={{ color: hov.delta > 0 ? "var(--color-severity-high-text)" : hov.delta < 0 ? "var(--color-status-ok-text)" : "var(--color-text-tertiary)" }}>
                {hov.delta > 0 ? "+" : ""}{hov.delta.toLocaleString()}
              </span>
            </span>
          </div>
        )}
      </div>
    </Card>
  )
}


// ── Severity mix (100% normalized) chart ────────────────────────────────────

/**
 * Severity composition over time as a 100%-normalized stacked area. Absolute
 * counts are shown elsewhere; this answers "is the mix getting more severe?"
 * independent of total volume.
 */
function SeverityMixChart({
  trend,
  rangeDays,
}: {
  trend: PostureTrendResponse
  rangeDays: PostureRange
}) {
  const [boxRef, W] = useMeasuredWidth<HTMLDivElement>()
  const gradId = `sevmix-${React.useId().replace(/:/g, "")}`
  const points = trend.points.filter((p) => p.total > 0)
  if (points.length < 2) return null

  const H = 200
  const PAD_L = 34
  const PAD_R = 10
  const PAD_T = 10
  const PAD_B = 24
  const plotW = Math.max(W - PAD_L - PAD_R, 0)
  const plotH = H - PAD_T - PAD_B
  const xOf = (i: number) => PAD_L + (plotW * i) / (points.length - 1)
  const yOf = (frac: number) => PAD_T + plotH - frac * plotH

  // Cumulative fraction per layer (low→critical), each point normalized to its total.
  const cum: number[][] = points.map(() => [0, 0, 0, 0])
  STACK_ORDER.forEach((layer, idx) => {
    points.forEach((p, i) => {
      const prev = idx === 0 ? 0 : cum[i][idx - 1]
      cum[i][idx] = prev + p[layer] / p.total
    })
  })

  function areaPath(layerIdx: number): string {
    const top = points.map((_, i) => `${i === 0 ? "M" : "L"}${xOf(i).toFixed(1)},${yOf(cum[i][layerIdx]).toFixed(1)}`).join(" ")
    if (layerIdx === 0) {
      return top + ` L${xOf(points.length - 1).toFixed(1)},${yOf(0).toFixed(1)} L${xOf(0).toFixed(1)},${yOf(0).toFixed(1)} Z`
    }
    const back = points.map((_, i) => {
      const idx = points.length - 1 - i
      return `L${xOf(idx).toFixed(1)},${yOf(cum[idx][layerIdx - 1]).toFixed(1)}`
    }).join(" ")
    return top + " " + back + " Z"
  }

  const last = points[points.length - 1]
  const critHighPct = Math.round(((last.critical + last.high) / last.total) * 100)

  return (
    <Card className="rounded-md">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
            Severity mix over time
          </h2>
          <span className="rounded-full bg-[var(--color-surface-muted)] px-2 py-0.5 text-2xs font-medium uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
            share of open
          </span>
        </div>
        <span className="text-2xs tabular-nums text-[var(--color-text-secondary)]">
          now <span className="font-semibold" style={{ color: "var(--color-severity-high-text)" }}>{critHighPct}%</span> high+critical
        </span>
      </div>

      <div ref={boxRef} className="relative" style={{ height: H }}>
        {W > 0 && (
          <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} className="block" role="img"
            aria-label="Severity composition of open findings over time, as a share of total">
            <defs>
              {STACK_ORDER.map((layer) => (
                <linearGradient key={layer} id={`${gradId}-${layer}`} x1="0" y1={PAD_T} x2="0" y2={PAD_T + plotH} gradientUnits="userSpaceOnUse">
                  <stop offset="0%" stopColor={STACK_FILL[layer].color} stopOpacity={STACK_FILL[layer].opacity} />
                  <stop offset="100%" stopColor={STACK_FILL[layer].color} stopOpacity={STACK_FILL[layer].opacity * 0.4} />
                </linearGradient>
              ))}
            </defs>
            <g fontSize="10" fill="var(--color-text-tertiary)">
              {[0, 0.5, 1].map((g) => (
                <text key={g} x="0" y={yOf(g) + 3.5}>{Math.round(g * 100)}%</text>
              ))}
            </g>
            {STACK_ORDER.map((layer, idx) => (
              <path
                key={layer}
                d={areaPath(idx)}
                fill={`url(#${gradId}-${layer})`}
                className="chart-rise"
                style={{ animationDelay: `${idx * 90}ms` }}
              />
            ))}
            <g fontSize="10" fill="var(--color-text-secondary)">
              <text x={PAD_L} y={H - 8}>{formatChartDate(points[0].date)}</text>
              <text x={PAD_L + plotW} y={H - 8} textAnchor="end" fill="var(--color-accent)">Today</text>
            </g>
          </svg>
        )}
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-3">
        {(["critical", "high", "medium", "low"] as const).map((layer) => (
          <span key={layer} className="flex items-center gap-1.5 text-2xs">
            <span className="inline-block h-2 w-2 rounded-sm shrink-0" style={{ background: SEV_VARS[layer] }} />
            <span className="capitalize text-[var(--color-text-secondary)]">{layer}</span>
          </span>
        ))}
      </div>
    </Card>
  )
}


// ── SLA compliance gauge ────────────────────────────────────────────────────

/**
 * Radial gauge: share of open findings currently within SLA vs breached.
 * within = total_open − total_breached (floored at zero for safety).
 */
function SlaComplianceGauge({
  snap,
  slaPosture,
}: {
  snap: PostureSnapshotResponse
  slaPosture?: SlaPostureSummary | null
}) {
  if (!slaPosture) return null
  const totalOpen = snap.counts.total
  if (totalOpen === 0) return null

  const breached = Math.min(slaPosture.totalBreached, totalOpen)
  const within = Math.max(totalOpen - breached, 0)
  const compliancePct = Math.round((within / totalOpen) * 100)

  // 270° sweep gauge starting from bottom-left.
  const size = 132
  const cx = size / 2
  const cy = size / 2
  const r = 52
  const stroke = 12
  const startAngle = 135
  const sweep = 270
  const circ = 2 * Math.PI * r
  const arcLen = (sweep / 360) * circ
  const filled = (compliancePct / 100) * arcLen

  const tone =
    compliancePct >= 90 ? "var(--color-status-ok)"
    : compliancePct >= 70 ? "var(--color-severity-medium)"
    : "var(--color-severity-critical)"
  const toneText =
    compliancePct >= 90 ? "var(--color-status-ok-text)"
    : compliancePct >= 70 ? "var(--color-severity-medium-text)"
    : "var(--color-severity-critical-text)"

  const bySev = [
    { key: "critical", label: "Critical", n: slaPosture.criticalBreached },
    { key: "high", label: "High", n: slaPosture.highBreached },
    { key: "medium", label: "Medium", n: slaPosture.mediumBreached },
    { key: "low", label: "Low", n: slaPosture.lowBreached },
  ].filter((s) => s.n > 0)

  return (
    <Card className="rounded-md">
      <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
        SLA compliance
      </h2>
      <div className="mt-3 flex items-center gap-5">
        <div className="relative shrink-0" style={{ width: size, height: size }}>
          <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img"
            aria-label={`${compliancePct}% of open findings within SLA`}>
            <circle
              cx={cx} cy={cy} r={r} fill="none"
              stroke="var(--color-surface-raised)" strokeWidth={stroke}
              strokeDasharray={`${arcLen} ${circ - arcLen}`} strokeLinecap="round"
              transform={`rotate(${startAngle} ${cx} ${cy})`}
            />
            <circle
              cx={cx} cy={cy} r={r} fill="none"
              stroke={tone} strokeWidth={stroke}
              strokeDasharray={`${filled} ${circ - filled}`} strokeLinecap="round"
              transform={`rotate(${startAngle} ${cx} ${cy})`}
              className="chart-arc-sweep"
              style={{ ["--arc-len" as string]: filled }}
            />
          </svg>
          <span className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-2xl font-bold leading-none tabular-nums" style={{ color: toneText }}>
              {compliancePct}%
            </span>
            <span className="mt-0.5 text-2xs font-mono font-medium uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
              within SLA
            </span>
          </span>
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-2">
            <span className="text-lg font-semibold tabular-nums text-[var(--color-text-primary)]">
              {within.toLocaleString()}
            </span>
            <span className="text-xs text-[var(--color-text-secondary)]">within SLA</span>
          </div>
          <div className="mt-0.5 flex items-baseline gap-2">
            <span className="text-lg font-semibold tabular-nums" style={{ color: "var(--color-severity-critical-text)" }}>
              {breached.toLocaleString()}
            </span>
            <span className="text-xs text-[var(--color-text-secondary)]">breached</span>
          </div>
          {bySev.length > 0 && (
            <div className="mt-2.5 flex flex-col gap-1 border-t border-[var(--color-border)] pt-2">
              {bySev.map((s) => (
                <div key={s.key} className="flex items-center gap-2 text-2xs">
                  <span className="inline-block h-2 w-2 rounded-full shrink-0" style={{ background: SEV_VARS[s.key as keyof typeof SEV_VARS] }} />
                  <span className="text-[var(--color-text-secondary)]">{s.label}</span>
                  <span className="ml-auto font-semibold tabular-nums text-[var(--color-text-primary)]">{s.n.toLocaleString()}</span>
                </div>
              ))}
            </div>
          )}
          {slaPosture.maxBreachAgeDays > 0 && (
            <p className="mt-2 text-2xs text-[var(--color-text-tertiary)]">
              Oldest breach: <span className="font-medium text-[var(--color-text-secondary)] tabular-nums">{slaPosture.maxBreachAgeDays}d</span> over target
            </p>
          )}
        </div>
      </div>
    </Card>
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
  /** Switch to the Triage tab (used by the risk-score hero "what drives this" link). */
  onSwitchToTriage?: () => void
  /** Exploitability summary for the KEV-exposed KPI. Null while loading / on failure. */
  exploitability?: ExploitabilitySummary | null
  /** SLA posture summary for the SLA-breached KPI. Null while loading / on failure. */
  slaPosture?: SlaPostureSummary | null
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
  onSwitchToTriage,
  exploitability,
  slaPosture,
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
        <RiskScoreHero
          snap={snap}
          trend={trend}
          rangeDays={rangeDays}
          onSwitchToTriage={onSwitchToTriage}
        />
        <KpiGrid
          snap={snap}
          trend={trend}
          slaSummary={slaSummary}
          exploitability={exploitability}
          slaPosture={slaPosture}
        />
      </div>

      <AttentionPanel snap={snap} teams={teams} exploitability={exploitability} slaPosture={slaPosture} />

      <div className="grid gap-5 lg:grid-cols-2">
        <RiskTrendChart
          trend={trend}
          rangeDays={rangeDays}
          color={getRatingTokens(snap.riskScore.rating).color}
        />
        <PostureTrendChart snap={snap} trend={trend} rangeDays={rangeDays} />
      </div>

      <DiscoveryVelocityChart trend={trend} rangeDays={rangeDays} />

      <div className="grid gap-5 lg:grid-cols-2">
        <BacklogFlowChart trend={trend} rangeDays={rangeDays} />
        <SeverityMixChart trend={trend} rangeDays={rangeDays} />
      </div>

      <div className="grid gap-5 lg:grid-cols-3">
        <SeverityDonut snap={snap} />
        <TeamRiskPanel teams={teams} />
        <TopReposPanel repos={snap.topRepositories} />
      </div>

      <div className="grid gap-5 lg:grid-cols-3">
        <RepositoryCoveragePanel snap={snap} />
        <SlaComplianceGauge snap={snap} slaPosture={slaPosture} />
        {snap.ageBuckets.length > 0 && <AgeBucketsPanel buckets={snap.ageBuckets} />}
      </div>

      <ComplianceSnapshot frameworks={frameworks} summaries={complianceSummaries} />
    </div>
  )
}
