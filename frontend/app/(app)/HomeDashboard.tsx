"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import Link from "next/link"
import { gqlQuery } from "@/lib/client/graphql-client"
import { formatPercentile, type EpssTopFinding } from "@/lib/client/epss-api"
import { listFindings, type Finding as ApiFinding } from "@/lib/client/findings-api"
import { HOME_DASHBOARD_QUERY } from "@/lib/shared/graphql/queries"
import type {
  GqlPostureTrendPoint,
  GqlHomeAnalytics,
  GqlHomeDashboard,
} from "@/lib/shared/graphql/types"
import { useSSE } from "@/components/providers/SSEProvider"
import { SetupChecklistCard } from "@/components/shared/SetupChecklistCard"
import { useCurrentUser } from "@/lib/client/auth"
import type { SourceConnection } from "@/lib/shared/sources-types"
import { EmptyOverviewBanner, GhostPreviewWrapper } from "@/components/shared/EmptyOverviewBanner"
import { Button } from "@/components/ui/Button"
import { HomeGhostPreview } from "./HomeGhostPreview"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

function getSalutation(date: Date): string {
  const h = date.getHours()
  if (h >= 5 && h < 12) return "Morning"
  if (h >= 12 && h < 17) return "Afternoon"
  if (h >= 17 && h < 21) return "Evening"
  return "Late"
}

interface ToolCounts {
  total: number
  critical: number
  high: number
  medium: number
  low: number
}

const EMPTY: ToolCounts = { total: 0, critical: 0, high: 0, medium: 0, low: 0 }

type LoadState = "loading" | "ok" | "error"

interface ToolRow {
  label: string
  href: string
  settingsHref: string
  counts: ToolCounts
  state: LoadState
  icon: string
}

const SEV_CLASSES = {
  critical: { dot: "bg-[var(--color-severity-critical)]", text: "text-[var(--color-severity-critical)]" },
  high: { dot: "bg-[var(--color-severity-high)]", text: "text-[var(--color-severity-high)]" },
  medium: { dot: "bg-[var(--color-severity-medium)]", text: "text-[var(--color-severity-medium)]" },
  low: { dot: "bg-[var(--color-severity-low)]", text: "text-[var(--color-severity-low)]" },
}

const LINK_FOCUS = "focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none focus-visible:rounded-lg"

// ── Open in your repos · CVE cards ────────────────────────────────────────────

interface OpenCveCard {
  cve: string
  identityKey: string
  primaryFindingId: number
  primaryRepo: string
  severity: string
  epssPercentile: number | null
  repoCount: number
  otherRepos: string[]
}

function buildOpenCveCards(findings: EpssTopFinding[], limit = 5): OpenCveCard[] {
  const byCve = new Map<string, EpssTopFinding[]>()
  for (const f of findings) {
    if (!f.cve) continue
    const bucket = byCve.get(f.cve)
    if (bucket) bucket.push(f)
    else byCve.set(f.cve, [f])
  }
  const cards: OpenCveCard[] = []
  for (const [cve, group] of byCve) {
    const primary = group[0]
    const otherRepos = group.slice(1).map(g => g.repo).filter((v, i, arr) => arr.indexOf(v) === i)
    cards.push({
      cve,
      identityKey: primary.identity_key,
      primaryFindingId: primary.finding_id,
      primaryRepo: primary.repo,
      severity: primary.severity,
      epssPercentile: Number.isFinite(primary.epss_percentile) ? primary.epss_percentile : null,
      repoCount: 1 + otherRepos.length,
      otherRepos,
    })
  }
  return cards.slice(0, limit)
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-[var(--color-severity-critical)]/10 text-[var(--color-severity-critical)]",
  high: "bg-[var(--color-severity-high)]/10 text-[var(--color-severity-high)]",
  medium: "bg-[var(--color-severity-medium)]/10 text-[var(--color-severity-medium)]",
  low: "bg-[var(--color-severity-low)]/10 text-[var(--color-severity-low)]",
}

function CveCard({ card }: { card: OpenCveCard }) {
  const sevKey = card.severity.toLowerCase()
  const sevClass = SEVERITY_BADGE[sevKey] ?? "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]"
  const percentileLabel = formatPercentile(card.epssPercentile ?? undefined)
  const multiRepo = card.repoCount > 1
  const locationLine = multiRepo && card.otherRepos.length > 0
    ? `also in ${card.otherRepos.slice(0, 2).join(", ")}${card.otherRepos.length > 2 ? ` +${card.otherRepos.length - 2}` : ""}`
    : null
  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      {/* Tag row — mock inherited-tag-row */}
      <div className="flex flex-wrap items-center gap-1.5">
        <span className={`rounded px-1.5 py-0.5 text-2xs font-semibold uppercase tracking-wide ${sevClass}`}>
          {card.severity || "unknown"}
        </span>
        {percentileLabel && (
          <span className="rounded bg-[var(--color-severity-high)]/10 px-1.5 py-0.5 text-2xs font-semibold text-[var(--color-severity-high)]">
            EPSS {percentileLabel}
          </span>
        )}
        <span className="rounded bg-[var(--color-surface-raised)] px-1.5 py-0.5 text-2xs text-[var(--color-text-secondary)]">
          {card.primaryRepo}
        </span>
        {multiRepo && (
          <span className="rounded bg-[var(--color-state-dismissed-subtle)] px-1.5 py-0.5 text-2xs font-medium text-[var(--color-state-dismissed)]">
            Affects {card.repoCount} of your repos
          </span>
        )}
      </div>

      {/* Title — mock inherited-title (16px / 600). CVE appears inline as the mock shows. */}
      <h3
        className="mt-3 truncate text-base font-semibold text-[var(--color-text-primary)]"
        title={card.identityKey}
      >
        {card.identityKey}
        {card.cve && (
          <span className="ml-2 font-[family-name:var(--font-jetbrains-mono)] text-sm font-normal text-[var(--color-text-tertiary)]">
            — {card.cve}
          </span>
        )}
      </h3>

      {/* Location / 'also in...' */}
      {locationLine && (
        <p className="mt-1 truncate text-xs text-[var(--color-text-secondary)]" title={card.otherRepos.join(", ")}>
          {locationLine}
        </p>
      )}

      {/* Open-fix-PR / Jira stay disabled until those integrations are wired through. */}
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <Link
          href={`/findings/${card.primaryFindingId}`}
          className={`inline-flex h-8 items-center gap-1.5 rounded-md bg-[var(--color-accent)] px-3 text-xs font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-surface)]`}
        >
          Investigate →
        </Link>
        <Button variant="secondary" size="sm" disabled title="Coming soon">
          Open fix PR
        </Button>
        <Button variant="ghost" size="sm" disabled title="Coming soon">
          Create Jira ticket
        </Button>
      </div>
    </div>
  )
}

// ── Just introduced · needs your attention ────────────────────────────────────

function formatRelative(iso: string | null | undefined): string {
  if (!iso) return ""
  const t = Date.parse(iso)
  if (!Number.isFinite(t)) return ""
  const diffMs = Date.now() - t
  const mins = Math.floor(diffMs / 60_000)
  if (mins < 1) return "just now"
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days < 30) return `${days}d ago`
  const months = Math.floor(days / 30)
  return `${months}mo ago`
}

const SCANNER_SHORT: Record<string, string> = {
  deps: "Dependencies",
  container: "Container",
  containers: "Container",
  sast: "Code Scanning",
  secrets: "Secrets",
  iac: "IaC",
}

function FeaturedFindingCard({ finding }: { finding: ApiFinding }) {
  const sevKey = (finding.severity || "").toLowerCase()
  const sevClass = SEVERITY_BADGE[sevKey] ?? "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]"
  const scannerLabel = SCANNER_SHORT[finding.scanner] ?? finding.scanner
  const fileLine = finding.file_path
    ? finding.line != null
      ? `${finding.file_path}:${finding.line}`
      : finding.file_path
    : null
  return (
    <Link
      href={`/findings/${finding.id}`}
      className={`block rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 transition-colors hover:border-[var(--color-border-strong)] hover:bg-[var(--color-surface-raised)] ${LINK_FOCUS}`}
    >
      {/* Sev chip + title row */}
      <div className="flex items-start gap-3">
        <span
          className={`inline-flex items-center gap-1.5 shrink-0 rounded px-2 py-0.5 text-2xs font-semibold uppercase tracking-wide ${sevClass}`}
        >
          <span
            aria-hidden="true"
            className="inline-block h-1.5 w-1.5 rounded-full bg-current"
          />
          {finding.severity || "unknown"}
        </span>
        <h3
          className="flex-1 min-w-0 text-base font-semibold text-[var(--color-text-primary)] tracking-[-0.005em]"
          title={finding.title ?? finding.cve ?? finding.id}
        >
          {finding.title ?? finding.cve ?? "Finding"}
        </h3>
        <svg className="h-3.5 w-3.5 shrink-0 text-[var(--color-text-tertiary)] transition-transform group-hover:translate-x-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="m9 18 6-6-6-6" />
        </svg>
      </div>

      {/* Meta line — repo · file · time · scanner */}
      <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-[var(--color-text-secondary)]">
        {finding.repo && (
          <span className="inline-flex items-center gap-1.5">
            <svg className="h-3 w-3 text-[var(--color-text-tertiary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} aria-hidden="true">
              <path d="M21 7.5l-9-5.25L3 7.5m18 0l-9 5.25m9-5.25v9l-9 5.25M3 7.5l9 5.25M3 7.5v9l9 5.25m0-9v9" />
            </svg>
            {finding.repo}
          </span>
        )}
        {fileLine && (
          <>
            <span className="text-[var(--color-text-tertiary)]" aria-hidden="true">·</span>
            <code className="rounded bg-[var(--color-surface-raised)] px-1.5 py-0.5 font-[family-name:var(--font-jetbrains-mono)] text-[11.5px] text-[var(--color-text-primary)]">
              {fileLine}
            </code>
          </>
        )}
        {finding.created_at && (
          <>
            <span className="text-[var(--color-text-tertiary)]" aria-hidden="true">·</span>
            <span className="text-[var(--color-text-tertiary)]">{formatRelative(finding.created_at)}</span>
          </>
        )}
        <span className="text-[var(--color-text-tertiary)]" aria-hidden="true">·</span>
        <span className="text-[var(--color-text-tertiary)]">{scannerLabel}{finding.cve ? ` · ${finding.cve}` : ""}</span>
      </div>
    </Link>
  )
}

function CompactFindingRow({ finding }: { finding: ApiFinding }) {
  const sevKey = (finding.severity || "").toLowerCase()
  const sevClass = SEVERITY_BADGE[sevKey] ?? "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]"
  const scannerLabel = SCANNER_SHORT[finding.scanner] ?? finding.scanner
  const fileLine = finding.file_path
    ? finding.line != null
      ? `${finding.file_path}:${finding.line}`
      : finding.file_path
    : null
  return (
    <Link
      href={`/findings/${finding.id}`}
      className={`group flex items-center gap-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3 transition-colors hover:border-[var(--color-border-strong)] hover:bg-[var(--color-surface-raised)] ${LINK_FOCUS}`}
    >
      <span
        className={`inline-flex shrink-0 items-center gap-1.5 rounded px-2 py-0.5 text-2xs font-semibold uppercase tracking-wide ${sevClass}`}
      >
        <span aria-hidden="true" className="inline-block h-1.5 w-1.5 rounded-full bg-current" />
        {finding.severity || "unknown"}
      </span>
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-medium text-[var(--color-text-primary)]">
          {finding.title ?? finding.cve ?? "Finding"}
        </div>
        <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-[var(--color-text-tertiary)]">
          {finding.repo && <span>{finding.repo}</span>}
          {fileLine && (
            <code className="font-[family-name:var(--font-jetbrains-mono)]">{fileLine}</code>
          )}
          <span>{scannerLabel}</span>
          {finding.created_at && <span>{formatRelative(finding.created_at)}</span>}
        </div>
      </div>
      <svg className="h-4 w-4 shrink-0 text-[var(--color-text-tertiary)] transition-transform group-hover:translate-x-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="m9 18 6-6-6-6" />
      </svg>
    </Link>
  )
}

function JustIntroducedSection({ findings }: { findings: ApiFinding[] | null }) {
  // findings === null while loading. Treat that the same as the no-data path —
  // the home shell renders its own skeleton during the initial load anyway.
  const hasData = findings !== null && findings.length > 0
  return (
    <section aria-labelledby="just-introduced-heading">
      <div className="mb-3 flex items-baseline justify-between gap-3">
        <h2
          id="just-introduced-heading"
          className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]"
        >
          Just introduced · needs your attention
        </h2>
        {hasData && findings && findings[0].created_at && (
          <span className="text-xs text-[var(--color-text-tertiary)]">
            {findings.length} {findings.length === 1 ? "finding" : "findings"} · {formatRelative(findings[0].created_at)}
          </span>
        )}
      </div>
      {hasData && findings ? (
        <div className="space-y-2">
          <FeaturedFindingCard finding={findings[0]} />
          {findings.length > 1 && <CompactFindingRow finding={findings[1]} />}
        </div>
      ) : (
        <div className="flex items-center gap-4 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
          <span
            aria-hidden="true"
            className="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-[var(--color-status-ok)]/10 text-[var(--color-status-ok)]"
          >
            <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
              <polyline points="22 4 12 14.01 9 11.01" />
            </svg>
          </span>
          <div className="min-w-0">
            <p className="text-sm font-medium text-[var(--color-text-primary)]">
              No open critical or high findings
            </p>
            <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
              Newly introduced high-severity findings will surface here as scans complete.
            </p>
          </div>
        </div>
      )}
    </section>
  )
}

function OpenInYourReposSection({ cards }: { cards: OpenCveCard[] }) {
  if (cards.length === 0) return null
  return (
    <section>
      <div className="mb-3 flex items-baseline justify-between">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
          Open in your repos
        </h2>
        <span className="text-xs text-[var(--color-text-tertiary)]">
          {cards.length} outstanding
        </span>
      </div>
      <div className="grid gap-3">
        {cards.map(card => (
          <CveCard key={`${card.cve}-${card.primaryFindingId}`} card={card} />
        ))}
      </div>
    </section>
  )
}

// ── Your week · stats + 7-day chart ───────────────────────────────────────────

interface WeekStats {
  introduced: number
  fixed: number
  net: number
  /** Difference vs the previous 7-day window — null when we don't have enough trend history. */
  introducedDelta: number | null
  fixedDelta: number | null
  /** Display range like 'May 26 – Jun 2'. */
  dateRange: string
  days: { date: string; label: string; introduced: number; fixed: number }[]
}

const DAY_LABELS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
const MONTH_SHORT = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

function sumWeekDeltas(points: GqlPostureTrendPoint[]): { introduced: number; fixed: number } {
  let introduced = 0
  let fixed = 0
  for (let i = 1; i < points.length; i++) {
    const delta = points[i].total - points[i - 1].total
    if (delta > 0) introduced += delta
    else if (delta < 0) fixed += -delta
  }
  return { introduced, fixed }
}

function formatDateRange(startIso: string, endIso: string): string {
  const start = new Date(startIso)
  const end = new Date(endIso)
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) return ""
  const startLabel = `${MONTH_SHORT[start.getMonth()]} ${start.getDate()}`
  const endLabel = `${MONTH_SHORT[end.getMonth()]} ${end.getDate()}`
  return `${startLabel} – ${endLabel}`
}

function buildWeekStats(points: GqlPostureTrendPoint[]): WeekStats | null {
  if (points.length < 2) return null
  const thisWeekSlice = points.slice(-8)
  if (thisWeekSlice.length < 2) return null
  const days: WeekStats["days"] = []
  let introduced = 0
  let fixed = 0
  for (let i = 1; i < thisWeekSlice.length; i++) {
    const prev = thisWeekSlice[i - 1]
    const curr = thisWeekSlice[i]
    const delta = curr.total - prev.total
    const dayIntroduced = delta > 0 ? delta : 0
    const dayFixed = delta < 0 ? -delta : 0
    introduced += dayIntroduced
    fixed += dayFixed
    const parsed = new Date(curr.date)
    const label = Number.isNaN(parsed.getTime()) ? "" : DAY_LABELS[parsed.getDay()]
    days.push({ date: curr.date, label, introduced: dayIntroduced, fixed: dayFixed })
  }

  // Last week's slice = points immediately preceding this week's window.
  // Need at least one extra point as the boundary, so 15 total minimum.
  let introducedDelta: number | null = null
  let fixedDelta: number | null = null
  if (points.length >= 15) {
    const lastWeekSlice = points.slice(-15, -7)
    const prev = sumWeekDeltas(lastWeekSlice)
    introducedDelta = introduced - prev.introduced
    fixedDelta = fixed - prev.fixed
  }

  const dateRange = formatDateRange(days[0]?.date ?? "", days[days.length - 1]?.date ?? "")

  return { introduced, fixed, net: introduced - fixed, introducedDelta, fixedDelta, dateRange, days }
}

function WeekChart({ days }: { days: WeekStats["days"] }) {
  const maxValue = Math.max(...days.map(d => Math.max(d.introduced, d.fixed)), 1)
  const w = 800
  const h = 80
  const padBottom = 16
  const usable = h - padBottom
  const slotW = w / days.length
  const barW = 10
  const gap = 3
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="mt-4 h-20 w-full" preserveAspectRatio="none" aria-label="Last 7 days introduced vs fixed">
      <g stroke="var(--color-border)" strokeWidth="1">
        <line x1="0" y1={usable * 0.33} x2={w} y2={usable * 0.33} strokeDasharray="2 4" />
        <line x1="0" y1={usable * 0.66} x2={w} y2={usable * 0.66} strokeDasharray="2 4" />
      </g>
      {days.map((d, i) => {
        const cx = slotW * i + slotW / 2
        const introH = (d.introduced / maxValue) * usable
        const fixedH = (d.fixed / maxValue) * usable
        return (
          <g key={d.date}>
            <rect
              x={cx - barW - gap / 2}
              y={usable - introH}
              width={barW}
              height={introH}
              rx={2}
              fill="var(--color-severity-high)"
              opacity={d.introduced > 0 ? 0.85 : 0}
            />
            <rect
              x={cx + gap / 2}
              y={usable - fixedH}
              width={barW}
              height={fixedH}
              rx={2}
              fill="var(--color-status-ok)"
              opacity={d.fixed > 0 ? 0.85 : 0}
            />
            <text x={cx} y={h - 2} textAnchor="middle" fontSize="9" fill="var(--color-text-tertiary)">
              {d.label}
            </text>
          </g>
        )
      })}
    </svg>
  )
}

function DeltaArrow({ delta, kind }: { delta: number | null; kind: "introduced" | "fixed" }) {
  if (delta === null || delta === 0) return null
  // Introduced going up is bad (high), going down is good (ok).
  // Fixed going up is good (ok), going down is bad (high).
  const goodDir = kind === "introduced" ? "down" : "up"
  const dir = delta > 0 ? "up" : "down"
  const cls = dir === goodDir ? "text-[var(--color-status-ok)]" : "text-[var(--color-severity-high)]"
  const arrow = dir === "up" ? "▲" : "▼"
  return (
    <span className={`ml-1.5 text-xs font-medium tabular-nums ${cls}`} aria-hidden="true">
      {arrow}
      {Math.abs(delta)}
    </span>
  )
}

function YourWeekSection({ stats }: { stats: WeekStats }) {
  const netClass =
    stats.net > 0
      ? "text-[var(--color-severity-high)]"
      : stats.net < 0
      ? "text-[var(--color-status-ok)]"
      : "text-[var(--color-text-primary)]"
  const netLabel = stats.net > 0 ? `+${stats.net}` : stats.net === 0 ? "0" : `−${Math.abs(stats.net)}`
  const rangeLabel = stats.dateRange || "Last 7 days"
  return (
    <section>
      <div className="mb-3 flex items-baseline justify-between">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
          Your week
        </h2>
        <span className="text-xs text-[var(--color-text-tertiary)]">{rangeLabel}</span>
      </div>
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
        <div className="grid grid-cols-3 gap-4">
          <div>
            <p className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
              Introduced
            </p>
            <p className="mt-2 flex items-baseline text-3xl font-semibold tabular-nums leading-none text-[var(--color-severity-high)]">
              {stats.introduced.toLocaleString()}
              <DeltaArrow delta={stats.introducedDelta} kind="introduced" />
            </p>
            <p className="mt-2 text-xs text-[var(--color-text-tertiary)]">vs last week</p>
          </div>
          <div>
            <p className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
              Fixed
            </p>
            <p className="mt-2 flex items-baseline text-3xl font-semibold tabular-nums leading-none text-[var(--color-status-ok)]">
              {stats.fixed.toLocaleString()}
              <DeltaArrow delta={stats.fixedDelta} kind="fixed" />
            </p>
            <p className="mt-2 text-xs text-[var(--color-text-tertiary)]">vs last week</p>
          </div>
          <div>
            <p className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
              Net change
            </p>
            <p className={`mt-2 text-3xl font-semibold tabular-nums leading-none ${netClass}`}>
              {netLabel}
            </p>
            <p className="mt-2 text-xs text-[var(--color-text-tertiary)]">in your repos</p>
          </div>
        </div>
        <div className="mt-5 border-t border-[var(--color-border)]/60 pt-2">
          <WeekChart days={stats.days} />
        </div>
      </div>
    </section>
  )
}

function ErrorBanner({ onRetry, retrying }: { onRetry: () => void; retrying: boolean }) {
  return (
    <div className="flex items-center justify-between rounded-2xl border border-[var(--color-severity-high)]/20 bg-[var(--color-severity-high)]/5 px-5 py-3">
      <div className="flex items-center gap-2 text-sm">
        <svg aria-hidden="true" className="h-4 w-4 shrink-0 text-[var(--color-severity-high)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
        </svg>
        <span className="text-[var(--color-text-primary)]">Some data failed to load.</span>
      </div>
      <Button variant="secondary" size="sm" onClick={onRetry} isLoading={retrying}>
        {retrying ? "Retrying..." : "Retry"}
      </Button>
    </div>
  )
}

// ── Your repos ────────────────────────────────────────────────────────────────

function YourReposList({ repos }: { repos: GqlHomeAnalytics["topRepositories"] }) {
  if (repos.length === 0) return null

  return (
    <section>
      <div className="mb-3 flex items-baseline justify-between">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
          Your repos
        </h2>
        <span className="text-xs text-[var(--color-text-tertiary)]">
          {repos.length} owned · ordered by issues
        </span>
      </div>
      <div className="space-y-1.5">
        {repos.map(repo => {
          const blocked = repo.critical > 0 || repo.high > 0
          const healthy = repo.open === 0
          const dotClass = blocked
            ? "bg-[var(--color-severity-critical)]"
            : healthy
            ? "bg-[var(--color-status-ok)]"
            : "bg-[var(--color-text-tertiary)]"
          const statusLabel = blocked ? "Blocked" : healthy ? "Healthy" : "Open"
          const detailParts: string[] = []
          if (repo.open > 0) detailParts.push(`${repo.open} ${repo.open === 1 ? "issue" : "issues"}`)
          if (repo.critical > 0) detailParts.push(`${repo.critical} critical`)
          if (repo.high > 0) detailParts.push(`${repo.high} high`)
          const detailText = detailParts.length > 0 ? detailParts.join(" · ") : "All clear"
          return (
            <Link
              key={repo.name}
              href={`/sources/${encodeURIComponent(repo.name)}`}
              className={`group flex items-center gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3 transition-colors hover:bg-[var(--color-bg-hover)] ${LINK_FOCUS}`}
            >
              <span className="sr-only">{statusLabel}: </span>
              <span aria-hidden="true" className={`h-1.5 w-1.5 shrink-0 rounded-full ${dotClass}`} />
              <span className="flex-1 truncate text-sm font-medium text-[var(--color-text-primary)]" title={repo.name}>
                {repo.name}
              </span>
              <span className={`shrink-0 text-xs tabular-nums ${blocked ? "text-[var(--color-severity-critical)]" : healthy ? "text-[var(--color-status-ok)]" : "text-[var(--color-text-secondary)]"}`}>
                {detailText}
              </span>
              <svg className="h-4 w-4 shrink-0 text-[var(--color-text-tertiary)] transition-transform group-hover:translate-x-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M9 18l6-6-6-6" /></svg>
            </Link>
          )
        })}
      </div>
    </section>
  )
}

// ── Main Dashboard ────────────────────────────────────────────────────────────

export function HomeDashboard() {
  const [deps, setDeps] = useState<ToolCounts>(EMPTY)
  const [code, setCode] = useState<ToolCounts>(EMPTY)
  const [containers, setContainers] = useState<ToolCounts>(EMPTY)
  const [secrets, setSecrets] = useState<ToolCounts>(EMPTY)
  const [depsState, setDepsState] = useState<LoadState>("loading")
  const [codeState, setCodeState] = useState<LoadState>("loading")
  const [containerState, setContainerState] = useState<LoadState>("loading")
  const [secretState, setSecretState] = useState<LoadState>("loading")
  const [sources, setSources] = useState<SourceConnection[]>([])
  const [sourcesState, setSourcesState] = useState<LoadState>("loading")
  const [trend, setTrend] = useState<GqlPostureTrendPoint[]>([])
  const [analytics, setAnalytics] = useState<GqlHomeAnalytics | null>(null)
  const [epssTop, setEpssTop] = useState<EpssTopFinding[] | null>(null)
  // Most-recent open critical/high findings — populates the 'Just introduced · needs your
  // attention' section. Independent of epssTop so the home query stays unchanged.
  const [recentFindings, setRecentFindings] = useState<ApiFinding[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [retrying, setRetrying] = useState(false)

  const loadAll = useCallback(async () => {
    setLoading(true)
    try {
      const data = await gqlQuery<GqlHomeDashboard>(HOME_DASHBOARD_QUERY, {
        trendDays: 30,
        epssLimit: 5,
      })

      setDeps(data.dependenciesCounts);     setDepsState("ok")
      setCode(data.codeScanningCounts);     setCodeState("ok")
      setContainers(data.containerCounts);  setContainerState("ok")
      setSecrets(data.secretCounts);        setSecretState("ok")

      // Map GraphQL connections to the SourceConnection shape expected by the UI.
      // Fields not returned by this query (scanScope, excludedItems, etc.) are
      // omitted here — the dashboard only reads status, name, auth, sourceType,
      // id, category, and discoveredItemCount (undefined is safe for the last one).
      setSources(
        data.sourceConnections.connections.map(c => ({
          id: c.id,
          sourceType: c.sourceType as SourceConnection["sourceType"],
          category: c.category as SourceConnection["category"],
          name: c.name,
          status: c.status as SourceConnection["status"],
          lastSyncedAt: c.lastSyncedAt ?? undefined,
          auth: { orgOrOwner: c.auth.orgOrOwner },
        } as SourceConnection)),
      )
      setSourcesState("ok")

      setTrend(data.postureTrend)
      setAnalytics(data.homeAnalytics)

      setEpssTop(
        data.epssTop.findings.map(f => ({
          finding_id: f.findingId,
          tool: f.tool,
          repo: f.repo,
          severity: f.severity,
          identity_key: f.identityKey,
          cve: f.cve,
          epss_score: f.epssScore,
          epss_percentile: f.epssPercentile,
          scored_date: f.scoredDate ?? null,
        } satisfies EpssTopFinding)),
      )

      // Fetch the 2 most-recently-introduced open critical/high findings for the
      // 'Just introduced' section. Reuses listFindings — no new endpoint needed.
      try {
        const recent = await listFindings({
          orgId: ORG_ID,
          severity: ["critical", "high"],
          state: ["open"],
          sort: "created_at",
          direction: "desc",
          limit: 2,
        })
        setRecentFindings(recent.findings)
      } catch {
        // Section falls back to the existing 'all clear' status card.
        setRecentFindings([])
      }
    } catch {
      setDepsState("error")
      setCodeState("error")
      setContainerState("error")
      setSecretState("error")
      setSourcesState("error")
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void loadAll() }, [loadAll])
  useSSE("scan.completed", () => { void loadAll() })
  useSSE("source.synced", () => { void loadAll() })

  const tools: ToolRow[] = [
    { label: "Dependencies", href: "/findings?scanner=deps", settingsHref: "/settings/dependencies", counts: deps, state: depsState, icon: "M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z" },
    { label: "Containers", href: "/findings?scanner=container", settingsHref: "/settings/containers", counts: containers, state: containerState, icon: "M21 7.5l-9-5.25L3 7.5m18 0l-9 5.25m9-5.25v9l-9 5.25M3 7.5l9 5.25M3 7.5v9l9 5.25m0-9v9" },
    { label: "Code Scanning", href: "/findings?scanner=sast", settingsHref: "/settings/code", counts: code, state: codeState, icon: "M17.25 6.75 22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3-4.5 16.5" },
    { label: "Secrets", href: "/findings?scanner=secrets", settingsHref: "/settings/secrets", counts: secrets, state: secretState, icon: "M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z" },
  ]

  const hasError = tools.some(t => t.state === "error") || sourcesState === "error"
  const loadedTools = tools.filter(t => t.state === "ok")
  const totalFindings = loadedTools.reduce((sum, t) => sum + t.counts.total, 0)
  const totalCritical = loadedTools.reduce((sum, t) => sum + t.counts.critical, 0)
  const totalHigh = loadedTools.reduce((sum, t) => sum + t.counts.high, 0)
  const totalMedium = loadedTools.reduce((sum, t) => sum + t.counts.medium, 0)
  const totalLow = loadedTools.reduce((sum, t) => sum + t.counts.low, 0)
  const healthySources = sources.filter(s => s.status === "connected" || s.status === "syncing").length
  const openCveCards = epssTop ? buildOpenCveCards(epssTop) : []
  const weekStats = buildWeekStats(trend)

  const { user, isLoading: userLoading } = useCurrentUser()
  const salutation = useMemo(() => getSalutation(new Date()), [])
  const displayName = userLoading ? "there" : user?.username ?? "there"
  const fixedRecently = analytics?.remediation.fixedLast30d ?? 0

  if (loading) {
    // Mirror the post-load shape: greeting + 4 sections (Just introduced, Open in your repos,
    // Your week, Your repos). Each section is a small header rectangle + a content block sized
    // to the real component so the layout doesn't reflow when data arrives.
    const sectionHeader = "h-3 w-28 motion-safe:animate-pulse rounded bg-[var(--color-surface-raised)]"
    const card = "motion-safe:animate-pulse rounded-2xl bg-[var(--color-surface-raised)]"
    return (
      <div className="space-y-8" aria-busy="true" aria-live="polite">
        {/* Greeting */}
        <div className="space-y-2">
          <div className="h-7 w-64 motion-safe:animate-pulse rounded bg-[var(--color-surface-raised)]" />
          <div className="h-4 w-80 motion-safe:animate-pulse rounded bg-[var(--color-surface-raised)]" />
        </div>
        {/* Just introduced */}
        <div className="space-y-3">
          <div className={sectionHeader} />
          <div className={`${card} h-24`} />
        </div>
        {/* Open in your repos */}
        <div className="space-y-3">
          <div className={sectionHeader} />
          <div className={`${card} h-32`} />
          <div className={`${card} h-32`} />
        </div>
        {/* Your week */}
        <div className="space-y-3">
          <div className={sectionHeader} />
          <div className={`${card} h-44`} />
        </div>
        {/* Your repos */}
        <div className="space-y-3">
          <div className={sectionHeader} />
          <div className={`${card} h-14`} />
          <div className={`${card} h-14`} />
        </div>
      </div>
    )
  }

  // Empty-state preview: when nothing's connected yet, render a dimmed ghost
  // of the populated layout so visitors can see what each section surfaces
  // after their first scan. recentFindings === null means the request never
  // ran (e.g. all queries failed); treat as empty for this check.
  const isEmpty =
    !hasError &&
    totalFindings === 0 &&
    sources.length === 0 &&
    (recentFindings === null || recentFindings.length === 0) &&
    openCveCards.length === 0 &&
    (analytics === null || analytics.topRepositories.length === 0)

  if (isEmpty) {
    return (
      <div className="space-y-6">
        <EmptyOverviewBanner />
        <GhostPreviewWrapper>
          <HomeGhostPreview displayName={displayName} salutation={salutation} />
        </GhostPreviewWrapper>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      {hasError && <ErrorBanner retrying={retrying} onRetry={async () => { setRetrying(true); await loadAll(); setRetrying(false) }} />}

      {/* Greeting — plain (no card chrome) per mock */}
      <div>
        <h1 className="text-[26px] font-bold leading-tight tracking-[-0.025em] text-[var(--color-text-primary)]">
          {salutation}, {displayName}
        </h1>
        <p
          className="mt-1 text-sm text-[var(--color-text-secondary)]"
          aria-busy={loading ? "true" : "false"}
        >
          {totalCritical > 0 && (
            <>
              <strong className={SEV_CLASSES.critical.text}>
                {totalCritical.toLocaleString()} critical
              </strong>
              {totalHigh > 0 ? " + " : " · "}
            </>
          )}
          {totalHigh > 0 && (
            <>
              <strong className={SEV_CLASSES.high.text}>
                {totalHigh.toLocaleString()} high
              </strong>
              {" · "}
            </>
          )}
          <strong className="text-[var(--color-text-primary)]">
            {totalFindings.toLocaleString()} {totalFindings === 1 ? "issue" : "issues"}
          </strong>{" "}
          open in your repos
          {fixedRecently > 0 && (
            <>
              {" · "}
              <strong className="text-[var(--color-status-ok)]">
                {fixedRecently.toLocaleString()} fixed
              </strong>{" "}
              in the last 30 days
            </>
          )}
        </p>
      </div>

      <JustIntroducedSection findings={recentFindings} />

      {/* Setup checklist · inline card; self-hides at 100% */}
      <SetupChecklistCard />

      {/* Open in your repos · inherited CVE cards */}
      {openCveCards.length > 0 && <OpenInYourReposSection cards={openCveCards} />}

      {/* Your week · 7-day summary */}
      {weekStats && <YourWeekSection stats={weekStats} />}

      {/* Your repos */}
      {analytics && analytics.topRepositories.length > 0 && (
        <YourReposList repos={analytics.topRepositories} />
      )}
    </div>
  )
}
