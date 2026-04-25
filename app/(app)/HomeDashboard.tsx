"use client"

import { useCallback, useEffect, useState } from "react"
import Link from "next/link"
import { gqlQuery } from "@/lib/client/graphql-client"
import {
  DEPENDENCIES_COUNTS_QUERY,
  CODE_SCANNING_COUNTS_QUERY,
  CONTAINER_COUNTS_QUERY,
  SECRET_COUNTS_QUERY,
  POSTURE_TREND_QUERY,
  HOME_ANALYTICS_QUERY,
} from "@/lib/shared/graphql/queries"
import type { GqlSeverityCounts, GqlPostureTrendPoint, GqlHomeAnalytics } from "@/lib/shared/graphql/types"
import { useSSE } from "@/components/providers/SSEProvider"
import { useLicense } from "@/lib/client/license/client"
import { listSourceConnections } from "@/lib/client/sources-api"
import type { SourceConnection } from "@/lib/shared/sources-types"

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

const SEV_VARS = {
  critical: "var(--color-severity-critical)",
  high: "var(--color-severity-high)",
  medium: "var(--color-severity-medium)",
  low: "var(--color-severity-low)",
}

const SEV_CLASSES = {
  critical: { dot: "bg-[var(--color-severity-critical)]", text: "text-[var(--color-severity-critical)]" },
  high: { dot: "bg-[var(--color-severity-high)]", text: "text-[var(--color-severity-high)]" },
  medium: { dot: "bg-[var(--color-severity-medium)]", text: "text-[var(--color-severity-medium)]" },
  low: { dot: "bg-[var(--color-severity-low)]", text: "text-[var(--color-severity-low)]" },
}

const LINK_FOCUS = "focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none focus-visible:rounded-lg"

// ── Posture Hero ─────────────────────────────────────────────────────────────

type Grade = { label: string; color: string; bg: string; border: string; summary: string }

function useGrade(totalCritical: number, totalHigh: number, totalFindings: number, noSources: boolean): Grade {
  if (noSources) return { label: "Unknown", color: "text-[var(--color-text-tertiary)]", bg: "", border: "border-[var(--color-border)]", summary: "No sources connected. Connect a repository or registry to start scanning." }
  if (totalCritical > 0) return { label: "Critical", color: "text-[var(--color-severity-critical)]", bg: "bg-[var(--color-severity-critical)]/[0.04]", border: "border-[var(--color-severity-critical)]/15", summary: `${totalCritical.toLocaleString()} critical finding${totalCritical === 1 ? "" : "s"} require immediate attention.` }
  if (totalHigh > 0) return { label: "At Risk", color: "text-[var(--color-severity-high)]", bg: "bg-[var(--color-severity-high)]/[0.04]", border: "border-[var(--color-severity-high)]/15", summary: `No critical findings, but ${totalHigh.toLocaleString()} high-severity finding${totalHigh === 1 ? "" : "s"} should be reviewed soon.` }
  if (totalFindings > 0) return { label: "Moderate", color: "text-[var(--color-severity-medium)]", bg: "bg-[var(--color-severity-medium)]/[0.03]", border: "border-[var(--color-severity-medium)]/15", summary: `${totalFindings.toLocaleString()} open finding${totalFindings === 1 ? "" : "s"}, none critical or high.` }
  return { label: "Healthy", color: "text-[var(--color-status-ok)]", bg: "bg-[var(--color-status-ok)]/[0.04]", border: "border-[var(--color-status-ok)]/15", summary: "No open findings. Your security posture is clean." }
}

function PostureHero({ grade, totalFindings, totalCritical, totalHigh, totalMedium, totalLow, actions }: {
  grade: Grade
  totalFindings: number
  totalCritical: number
  totalHigh: number
  totalMedium: number
  totalLow: number
  actions: ActionItem[]
}) {
  return (
    <div className={`rounded-2xl border ${grade.border} ${grade.bg} overflow-hidden`}>
      <div className="px-6 pt-5 pb-4">
        <div className="flex items-start justify-between gap-6">
          <div>
            <span className={`text-2xl font-semibold ${grade.color}`}>
              {grade.label}
            </span>
            <p className="mt-1 text-sm text-[var(--color-text-secondary)] max-w-lg">{grade.summary}</p>
          </div>
          {totalFindings > 0 && (
            <div className="flex items-end gap-5 shrink-0">
              <div className="text-right">
                <span className="text-3xl font-bold tabular-nums text-[var(--color-text-primary)] leading-none">{totalFindings.toLocaleString()}</span>
                <p className="mt-0.5 text-[10px] font-medium uppercase tracking-wider text-[var(--color-text-tertiary)]">open</p>
              </div>
              {totalCritical > 0 && (
                <div className="text-right">
                  <span className={`text-3xl font-bold tabular-nums leading-none ${SEV_CLASSES.critical.text}`}>{totalCritical.toLocaleString()}</span>
                  <p className="mt-0.5 text-[10px] font-medium uppercase tracking-wider text-[var(--color-text-tertiary)]">critical</p>
                </div>
              )}
              {totalHigh > 0 && (
                <div className="text-right">
                  <span className={`text-3xl font-bold tabular-nums leading-none ${SEV_CLASSES.high.text}`}>{totalHigh.toLocaleString()}</span>
                  <p className="mt-0.5 text-[10px] font-medium uppercase tracking-wider text-[var(--color-text-tertiary)]">high</p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Severity bar */}
        {totalFindings > 0 && (
          <div className="mt-4 flex h-2 overflow-hidden rounded-full bg-[var(--color-surface-raised)]">
            {totalCritical > 0 && <span className="h-full" style={{ width: `${(totalCritical / totalFindings) * 100}%`, background: SEV_VARS.critical }} />}
            {totalHigh > 0 && <span className="h-full" style={{ width: `${(totalHigh / totalFindings) * 100}%`, background: SEV_VARS.high }} />}
            {totalMedium > 0 && <span className="h-full" style={{ width: `${(totalMedium / totalFindings) * 100}%`, background: SEV_VARS.medium }} />}
            {totalLow > 0 && <span className="h-full" style={{ width: `${(totalLow / totalFindings) * 100}%`, background: SEV_VARS.low }} />}
          </div>
        )}
      </div>

      {/* Action items */}
      {actions.length > 0 && (
        <div className="border-t border-[var(--color-border)]/50 divide-y divide-[var(--color-border)]/50">
          {actions.map((action, i) => (
            <div key={i} className="flex items-center gap-3 px-6 py-2.5">
              <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${ACTION_STYLES[action.severity].dot}`} aria-hidden="true" />
              <span className="flex-1 text-xs text-[var(--color-text-primary)]">{action.text}</span>
              <Link
                href={action.href}
                className={`shrink-0 rounded-md px-2.5 py-1 text-[11px] font-semibold text-[var(--color-accent)] transition-colors hover:bg-[var(--color-accent)]/10 ${LINK_FOCUS}`}
              >
                {action.cta} →
              </Link>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Charts ────────────────────────────────────────────────────────────────────

function TrendChart({ points }: { points: GqlPostureTrendPoint[] }) {
  if (points.length < 2) return null
  const maxTotal = Math.max(...points.map(p => p.total), 1)
  const maxCrit = Math.max(...points.map(p => p.critical + p.high), 1)
  const w = 100
  const h = 40
  const step = w / (points.length - 1)

  function line(accessor: (p: GqlPostureTrendPoint) => number, max: number): string {
    return points
      .map((p, i) => {
        const x = i * step
        const y = h - (accessor(p) / max) * (h - 4) - 2
        return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`
      })
      .join(" ")
  }

  const first = points[0]
  const last = points[points.length - 1]
  const delta = last.total - first.total
  const critDelta = (last.critical + last.high) - (first.critical + first.high)
  const improving = delta <= 0 && critDelta <= 0 && first.total > 0

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
            30-day trend
          </p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            {improving ? (
              <span className="text-[var(--color-status-ok)]">Improving: findings decreasing</span>
            ) : delta > 0 ? (
              <span className="text-[var(--color-severity-high)]">+{delta.toLocaleString()} in 30 days</span>
            ) : first.total === 0 && last.total === 0 ? (
              "No findings recorded yet"
            ) : (
              "Stable"
            )}
          </p>
        </div>
        <div className="text-right">
          <span className="text-xl font-bold tabular-nums text-[var(--color-text-primary)] leading-none">{last.total.toLocaleString()}</span>
          <p className="text-[10px] text-[var(--color-text-tertiary)]">today</p>
        </div>
      </div>
      <svg viewBox={`0 0 ${w} ${h}`} className="mt-3 w-full h-14" preserveAspectRatio="none" aria-label="Findings trend over 30 days">
        <path d={line(p => p.total, maxTotal)} fill="none" stroke="var(--color-text-tertiary)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
        <path d={line(p => p.critical + p.high, maxCrit > 0 ? maxTotal : 1)} fill="none" stroke="var(--color-severity-critical)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" vectorEffect="non-scaling-stroke" opacity="0.7" />
      </svg>
      <div className="mt-2 flex items-center gap-4 text-[10px] text-[var(--color-text-tertiary)]">
        <span className="flex items-center gap-1"><span className="inline-block h-px w-3 bg-[var(--color-text-tertiary)]" /> Total</span>
        <span className="flex items-center gap-1"><span className="inline-block h-px w-3 bg-[var(--color-severity-critical)]" style={{ opacity: 0.7 }} /> Critical + High</span>
      </div>
    </div>
  )
}

function SeverityDonut({ counts }: { counts: ToolCounts }) {
  if (counts.total === 0) return null
  const segments = (["critical", "high", "medium", "low"] as const)
    .map(key => ({ key, value: counts[key] }))
    .filter(s => s.value > 0)

  const r = 42
  const stroke = 12
  const circ = 2 * Math.PI * r
  let offset = 0

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        Severity breakdown
      </p>
      <div className="mt-4 flex items-center gap-6">
        <div className="relative shrink-0">
          <svg width="108" height="108" viewBox="0 0 108 108" role="img" aria-label={`${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low`}>
            <circle cx="54" cy="54" r={r} fill="none" stroke="var(--color-surface-raised)" strokeWidth={stroke} />
            {segments.map(seg => {
              const pct = seg.value / counts.total
              const dashLen = pct * circ
              const dashOffset = -offset * circ
              offset += pct
              return (
                <circle
                  key={seg.key}
                  cx="54" cy="54" r={r}
                  fill="none"
                  stroke={SEV_VARS[seg.key]}
                  strokeWidth={stroke}
                  strokeDasharray={`${dashLen} ${circ - dashLen}`}
                  strokeDashoffset={dashOffset}
                  strokeLinecap="butt"
                  transform="rotate(-90 54 54)"
                />
              )
            })}
          </svg>
          <span className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-xl font-bold tabular-nums text-[var(--color-text-primary)]">{counts.total.toLocaleString()}</span>
            <span className="text-[10px] text-[var(--color-text-tertiary)]">total</span>
          </span>
        </div>
        <div className="flex flex-col gap-2.5">
          {segments.map(seg => (
            <span key={seg.key} className="flex items-center gap-2 text-xs">
              <span className="h-3 w-3 rounded" style={{ background: SEV_VARS[seg.key] }} aria-hidden="true" />
              <span className="min-w-[52px] capitalize text-[var(--color-text-secondary)]">{seg.key}</span>
              <span className="tabular-nums font-semibold text-[var(--color-text-primary)]">{seg.value.toLocaleString()}</span>
              <span className="text-[var(--color-text-tertiary)]">{Math.round((seg.value / counts.total) * 100)}%</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}

function MiniSparkline({ points, color }: { points: number[]; color: string }) {
  if (points.length < 2) return null
  const max = Math.max(...points, 1)
  const w = 48
  const h = 16
  const step = w / (points.length - 1)
  const d = points
    .map((v, i) => `${i === 0 ? "M" : "L"}${(i * step).toFixed(1)},${(h - (v / max) * (h - 2) - 1).toFixed(1)}`)
    .join(" ")
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} className="shrink-0" aria-hidden="true">
      <path d={d} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

// ── Actions ───────────────────────────────────────────────────────────────────

interface ActionItem { text: string; href: string; cta: string; severity: "critical" | "warn" | "info" }

const ACTION_STYLES: Record<ActionItem["severity"], { dot: string }> = {
  critical: { dot: "bg-[var(--color-severity-critical)]" },
  warn: { dot: "bg-[var(--color-severity-high)]" },
  info: { dot: "bg-[var(--color-accent)]" },
}

function buildActions(tools: ToolRow[], sources: SourceConnection[], sourcesState: LoadState): ActionItem[] {
  const loaded = tools.filter(t => t.state === "ok")
  const actions: ActionItem[] = []

  const worstTool = loaded.filter(t => t.counts.critical > 0).sort((a, b) => b.counts.critical - a.counts.critical)[0]
  const highTool = !worstTool ? loaded.filter(t => t.counts.high > 0).sort((a, b) => b.counts.high - a.counts.high)[0] : null

  if (worstTool) {
    actions.push({ severity: "critical", text: `Triage ${worstTool.counts.critical.toLocaleString()} critical findings in ${worstTool.label}`, href: worstTool.href, cta: "Review now" })
  }
  if (highTool) {
    actions.push({ severity: "warn", text: `Review ${highTool.counts.high.toLocaleString()} high-severity findings in ${highTool.label}`, href: highTool.href, cta: "Review" })
  }
  const errorSources = sources.filter(s => s.status === "error" || s.status === "disconnected")
  if (errorSources.length > 0) {
    const src = errorSources[0]
    actions.push({ severity: "warn", text: `Fix ${src.status} source "${src.name || src.auth?.orgOrOwner || src.sourceType}"`, href: `/sources/${src.category}/${src.id}`, cta: "Fix" })
  }
  const unconfigured = loaded.filter(t => t.counts.total === 0)
  if (sources.length > 0 && unconfigured.length > 0 && loaded.some(t => t.counts.total > 0)) {
    actions.push({ severity: "info", text: `${unconfigured.map(t => t.label).join(", ")} ${unconfigured.length === 1 ? "has" : "have"} no findings yet`, href: unconfigured[0].settingsHref, cta: "Configure" })
  }
  if (sourcesState === "ok" && sources.length === 0) {
    actions.push({ severity: "info", text: "Connect a source to start scanning", href: "/sources/code-repositories", cta: "Add source" })
  }
  return actions
}

// ── Error Banner ──────────────────────────────────────────────────────────────

// ── Analytics Charts ──────────────────────────────────────────────────────────

function TopReposChart({ repos }: { repos: GqlHomeAnalytics["topRepositories"] }) {
  if (repos.length === 0) return null
  const maxOpen = Math.max(...repos.map(r => r.open), 1)
  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        Top repositories by findings
      </p>
      <div className="mt-4 space-y-3">
        {repos.map(repo => (
          <div key={repo.name}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-medium text-[var(--color-text-primary)] truncate max-w-[200px]" title={repo.name}>{repo.name}</span>
              <span className="flex items-center gap-2 text-[11px] tabular-nums shrink-0">
                {repo.critical > 0 && <span className={SEV_CLASSES.critical.text}>{repo.critical}</span>}
                {repo.high > 0 && <span className={SEV_CLASSES.high.text}>{repo.high}</span>}
                <span className="text-[var(--color-text-secondary)]">{repo.open}</span>
              </span>
            </div>
            <div className="flex h-2 overflow-hidden rounded-full bg-[var(--color-surface-raised)]" style={{ width: `${Math.max((repo.open / maxOpen) * 100, 8)}%` }}>
              {repo.critical > 0 && <span className="h-full" style={{ width: `${(repo.critical / repo.open) * 100}%`, background: SEV_VARS.critical }} />}
              {repo.high > 0 && <span className="h-full" style={{ width: `${(repo.high / repo.open) * 100}%`, background: SEV_VARS.high }} />}
              <span className="h-full flex-1" style={{ background: SEV_VARS.medium, opacity: 0.5 }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function AgeBucketsChart({ buckets }: { buckets: GqlHomeAnalytics["ageBuckets"] }) {
  const total = buckets.reduce((sum, b) => sum + b.count, 0)
  if (total === 0) return null
  const maxCount = Math.max(...buckets.map(b => b.count), 1)
  const ageColors = ["var(--color-accent)", "var(--color-severity-medium)", "var(--color-severity-high)", "var(--color-severity-critical)"]
  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        Finding age distribution
      </p>
      <div className="mt-4 space-y-2.5">
        {buckets.map((bucket, i) => (
          <div key={bucket.label} className="flex items-center gap-3">
            <span className="min-w-[64px] text-right text-[11px] tabular-nums text-[var(--color-text-tertiary)]">{bucket.label}</span>
            <div className="h-5 flex-1 overflow-hidden rounded bg-[var(--color-surface-raised)]">
              <div className="h-full rounded" style={{ width: `${(bucket.count / maxCount) * 100}%`, background: ageColors[i] ?? ageColors[3], opacity: 0.7 }} />
            </div>
            <span className="min-w-[32px] text-xs tabular-nums font-medium text-[var(--color-text-primary)]">{bucket.count.toLocaleString()}</span>
          </div>
        ))}
      </div>
      {buckets.length >= 4 && buckets[3].count > 0 && (
        <p className="mt-3 text-[11px] text-[var(--color-severity-critical)]">
          {buckets[3].count.toLocaleString()} findings are over 90 days old
        </p>
      )}
    </div>
  )
}

function RemediationCard({ stats }: { stats: GqlHomeAnalytics["remediation"] }) {
  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        Remediation
      </p>
      <div className="mt-4 grid grid-cols-2 gap-4">
        <div>
          <span className="text-2xl font-bold tabular-nums text-[var(--color-text-primary)] leading-none">{stats.fixedLast30d.toLocaleString()}</span>
          <p className="mt-1 text-[11px] text-[var(--color-text-tertiary)]">fixed last 30 days</p>
        </div>
        <div>
          <span className="text-2xl font-bold tabular-nums text-[var(--color-text-primary)] leading-none">{stats.totalFixed.toLocaleString()}</span>
          <p className="mt-1 text-[11px] text-[var(--color-text-tertiary)]">total fixed</p>
        </div>
        <div>
          <span className="text-2xl font-bold tabular-nums text-[var(--color-text-primary)] leading-none">
            {stats.medianDays != null ? `${stats.medianDays}d` : "N/A"}
          </span>
          <p className="mt-1 text-[11px] text-[var(--color-text-tertiary)]">median time to fix</p>
        </div>
        <div>
          <span className="text-2xl font-bold tabular-nums text-[var(--color-text-primary)] leading-none">
            {stats.avgDays != null ? `${stats.avgDays}d` : "N/A"}
          </span>
          <p className="mt-1 text-[11px] text-[var(--color-text-tertiary)]">average time to fix</p>
        </div>
      </div>
    </div>
  )
}

// ── Argus Threat Intelligence Teaser ──────────────────────────────────────────

const FAKE_THREAT_DATA = [
  { label: "Exploited in the wild", value: 23, pct: 62 },
  { label: "Weaponized (PoC available)", value: 47, pct: 34 },
  { label: "No known exploit", value: 89, pct: 4 },
]

const FAKE_EPSS_BARS = [
  { label: "> 90%", count: 8 },
  { label: "70-90%", count: 15 },
  { label: "40-70%", count: 31 },
  { label: "10-40%", count: 52 },
  { label: "< 10%", count: 89 },
]

function ArgusTeaser({ isEnterprise }: { isEnterprise: boolean }) {
  return (
    <div className="relative">
      <div className={isEnterprise ? "" : "select-none pointer-events-none"}>
        <div className={isEnterprise ? "" : "blur-[3px] opacity-60"}>
          <div className="grid gap-5 lg:grid-cols-2">
            {/* Threat exploitability */}
            <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
              <div className="flex items-center gap-2">
                <svg className="h-4 w-4 text-purple-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 9v3.75m0-10.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z" />
                </svg>
                <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
                  Threat exploitability
                </p>
              </div>
              <div className="mt-4 space-y-3">
                {FAKE_THREAT_DATA.map(row => (
                  <div key={row.label}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-[var(--color-text-primary)]">{row.label}</span>
                      <span className="text-xs tabular-nums font-semibold text-[var(--color-text-primary)]">{row.value}</span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-[var(--color-surface-raised)]">
                      <div className="h-full rounded-full bg-purple-500" style={{ width: `${row.pct}%`, opacity: 0.7 }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* EPSS score distribution */}
            <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
              <div className="flex items-center gap-2">
                <svg className="h-4 w-4 text-purple-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                  <path d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 0 1 3 19.875v-6.75ZM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 0 1-1.125-1.125V8.625ZM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 0 1-1.125-1.125V4.125Z" />
                </svg>
                <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
                  EPSS score distribution
                </p>
              </div>
              <div className="mt-4 space-y-2">
                {FAKE_EPSS_BARS.map(bar => {
                  const max = Math.max(...FAKE_EPSS_BARS.map(b => b.count))
                  return (
                    <div key={bar.label} className="flex items-center gap-3">
                      <span className="min-w-[48px] text-right text-[11px] tabular-nums text-[var(--color-text-tertiary)]">{bar.label}</span>
                      <div className="h-5 flex-1 overflow-hidden rounded bg-[var(--color-surface-raised)]">
                        <div className="h-full rounded bg-purple-500/50" style={{ width: `${(bar.count / max) * 100}%` }} />
                      </div>
                      <span className="min-w-[24px] text-xs tabular-nums font-medium text-[var(--color-text-primary)]">{bar.count}</span>
                    </div>
                  )
                })}
              </div>
              <p className="mt-3 text-[10px] text-[var(--color-text-tertiary)]">
                EPSS: Exploit Prediction Scoring System. Higher score = higher likelihood of exploitation.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Upgrade overlay for community users */}
      {!isEnterprise && (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="rounded-2xl border border-purple-500/20 bg-[var(--color-surface)]/95 px-8 py-6 text-center shadow-lg backdrop-blur-sm max-w-sm">
            <div className="mx-auto flex h-10 w-10 items-center justify-center rounded-xl bg-purple-500/10">
              <svg className="h-5 w-5 text-purple-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 9v3.75m0-10.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z" />
              </svg>
            </div>
            <p className="mt-3 text-sm font-semibold text-[var(--color-text-primary)]">
              Blu3Raven Argus
            </p>
            <p className="mt-1.5 text-xs text-[var(--color-text-secondary)] leading-relaxed">
              AI-powered threat intelligence with EPSS scores, exploit availability, and advisory enrichment for every finding.
            </p>
            <Link
              href="/settings/license"
              className={`mt-4 inline-block rounded-lg border border-purple-500/20 bg-purple-500/10 px-4 py-2 text-sm font-semibold text-purple-400 transition-colors hover:bg-purple-500/20 ${LINK_FOCUS}`}
            >
              Activate Argus
            </Link>
          </div>
        </div>
      )}
    </div>
  )
}

function ErrorBanner({ onRetry, retrying }: { onRetry: () => void; retrying: boolean }) {
  return (
    <div className="flex items-center justify-between rounded-2xl border border-[var(--color-severity-high)]/20 bg-[var(--color-severity-high)]/5 px-5 py-3">
      <div className="flex items-center gap-2 text-sm">
        <svg className="h-4 w-4 shrink-0 text-[var(--color-severity-high)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
        </svg>
        <span className="text-[var(--color-text-primary)]">Some data failed to load.</span>
      </div>
      <button
        type="button"
        onClick={onRetry}
        disabled={retrying}
        className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-primary)] transition-colors hover:bg-[var(--color-surface-raised)] focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none disabled:opacity-50"
      >
        {retrying ? "Retrying..." : "Retry"}
      </button>
    </div>
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
  const [loading, setLoading] = useState(true)
  const [retrying, setRetrying] = useState(false)

  const loadAll = useCallback(async () => {
    const [d, cs, co, s, src, tr, ha] = await Promise.all([
      gqlQuery<{ dependenciesCounts: GqlSeverityCounts }>(DEPENDENCIES_COUNTS_QUERY, {}).then(r => ({ ok: true as const, data: r })).catch(() => ({ ok: false as const })),
      gqlQuery<{ codeScanningCounts: GqlSeverityCounts }>(CODE_SCANNING_COUNTS_QUERY, {}).then(r => ({ ok: true as const, data: r })).catch(() => ({ ok: false as const })),
      gqlQuery<{ containerCounts: GqlSeverityCounts }>(CONTAINER_COUNTS_QUERY, {}).then(r => ({ ok: true as const, data: r })).catch(() => ({ ok: false as const })),
      gqlQuery<{ secretCounts: GqlSeverityCounts }>(SECRET_COUNTS_QUERY, {}).then(r => ({ ok: true as const, data: r })).catch(() => ({ ok: false as const })),
      listSourceConnections().catch(() => null),
      gqlQuery<{ postureTrend: GqlPostureTrendPoint[] }>(POSTURE_TREND_QUERY, { days: 30 }).catch(() => null),
      gqlQuery<{ homeAnalytics: GqlHomeAnalytics }>(HOME_ANALYTICS_QUERY, {}).catch(() => null),
    ])
    if (d.ok) { setDeps(d.data.dependenciesCounts); setDepsState("ok") } else { setDepsState("error") }
    if (cs.ok) { setCode(cs.data.codeScanningCounts); setCodeState("ok") } else { setCodeState("error") }
    if (co.ok) { setContainers(co.data.containerCounts); setContainerState("ok") } else { setContainerState("error") }
    if (s.ok) { setSecrets(s.data.secretCounts); setSecretState("ok") } else { setSecretState("error") }
    if (src && src.ok) { setSources(src.data.connections); setSourcesState("ok") } else { setSourcesState("error") }
    if (tr) { setTrend(tr.postureTrend) }
    if (ha) { setAnalytics(ha.homeAnalytics) }
    setLoading(false)
  }, [])

  useEffect(() => { void loadAll() }, [loadAll])
  useSSE("scan.completed", () => { void loadAll() })
  useSSE("source.synced", () => { void loadAll() })

  const tools: ToolRow[] = [
    { label: "Dependencies", href: "/dependencies/dashboard", settingsHref: "/dependencies/dashboard?tab=settings", counts: deps, state: depsState, icon: "M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z" },
    { label: "Containers", href: "/containers/dashboard", settingsHref: "/containers/dashboard?tab=settings", counts: containers, state: containerState, icon: "M21 7.5l-9-5.25L3 7.5m18 0l-9 5.25m9-5.25v9l-9 5.25M3 7.5l9 5.25M3 7.5v9l9 5.25m0-9v9" },
    { label: "Code Scanning", href: "/code/dashboard", settingsHref: "/code/dashboard?tab=settings", counts: code, state: codeState, icon: "M17.25 6.75 22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3-4.5 16.5" },
    { label: "Secrets", href: "/secrets/dashboard", settingsHref: "/secrets/dashboard?tab=settings", counts: secrets, state: secretState, icon: "M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z" },
  ]

  const hasError = tools.some(t => t.state === "error") || sourcesState === "error"
  const loadedTools = tools.filter(t => t.state === "ok")
  const totalFindings = loadedTools.reduce((sum, t) => sum + t.counts.total, 0)
  const totalCritical = loadedTools.reduce((sum, t) => sum + t.counts.critical, 0)
  const totalHigh = loadedTools.reduce((sum, t) => sum + t.counts.high, 0)
  const totalMedium = loadedTools.reduce((sum, t) => sum + t.counts.medium, 0)
  const totalLow = loadedTools.reduce((sum, t) => sum + t.counts.low, 0)
  const healthySources = sources.filter(s => s.status === "connected" || s.status === "syncing").length
  const issueSources = sources.filter(s => s.status === "error" || s.status === "disconnected").length
  const noSources = sourcesState === "ok" && sources.length === 0

  const { tier, addons } = useLicense()
  const isEnterprise = tier === "enterprise"
  const hasArgus = addons?.includes("argus") ?? false
  const grade = useGrade(totalCritical, totalHigh, totalFindings, noSources)
  const actions = buildActions(tools, sources, sourcesState)

  if (loading) {
    return (
      <div className="space-y-5">
        <div className="h-8 w-48 motion-safe:animate-pulse rounded-lg bg-[var(--color-surface-raised)]" />
        <div className="h-32 motion-safe:animate-pulse rounded-2xl bg-[var(--color-surface-raised)]" />
        <div className="grid gap-5 lg:grid-cols-2">
          <div className="h-44 motion-safe:animate-pulse rounded-2xl bg-[var(--color-surface-raised)]" />
          <div className="h-44 motion-safe:animate-pulse rounded-2xl bg-[var(--color-surface-raised)]" />
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-5">
      <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        Security Posture
      </p>

      {hasError && <ErrorBanner retrying={retrying} onRetry={async () => { setRetrying(true); await loadAll(); setRetrying(false) }} />}

      {/* Hero: posture grade + metrics + actions */}
      <PostureHero
        grade={grade}
        totalFindings={totalFindings}
        totalCritical={totalCritical}
        totalHigh={totalHigh}
        totalMedium={totalMedium}
        totalLow={totalLow}
        actions={actions}
      />

      {/* Charts */}
      {(totalFindings > 0 || trend.length >= 2) && (
        <div className="grid gap-5 lg:grid-cols-2">
          {trend.length >= 2 ? (
            <TrendChart points={trend} />
          ) : (
            <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 flex flex-col justify-center">
              <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">30-day trend</p>
              <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
                Trend data will appear after scans run across multiple days.
              </p>
            </div>
          )}
          <SeverityDonut counts={{ total: totalFindings, critical: totalCritical, high: totalHigh, medium: totalMedium, low: totalLow }} />
        </div>
      )}

      {/* Analytics: top repos, age distribution, remediation */}
      {analytics && totalFindings > 0 && (
        <div className="grid gap-5 lg:grid-cols-3">
          <TopReposChart repos={analytics.topRepositories} />
          <AgeBucketsChart buckets={analytics.ageBuckets} />
          <RemediationCard stats={analytics.remediation} />
        </div>
      )}

      {/* Argus threat intelligence */}
      {totalFindings > 0 && <ArgusTeaser isEnterprise={hasArgus} />}

      {/* Tool breakdown */}
      <div>
        <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)] mb-3">Tools</p>
        <div className="grid gap-3 sm:grid-cols-2">
          {tools.map(tool => {
            if (tool.state === "error") {
              return (
                <div key={tool.label} className="flex items-center gap-3 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3.5">
                  <svg className="h-5 w-5 shrink-0 text-[var(--color-text-tertiary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round"><path d={tool.icon} /></svg>
                  <span className="text-sm font-semibold text-[var(--color-text-primary)]">{tool.label}</span>
                  <span className="ml-auto text-xs text-[var(--color-severity-high)]">Failed to load</span>
                </div>
              )
            }
            if (tool.state === "loading") {
              return (
                <div key={tool.label} className="flex items-center gap-3 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3.5">
                  <svg className="h-5 w-5 shrink-0 text-[var(--color-text-tertiary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round"><path d={tool.icon} /></svg>
                  <span className="text-sm font-semibold text-[var(--color-text-primary)]">{tool.label}</span>
                  <span className="ml-auto text-xs text-[var(--color-text-tertiary)]">Loading...</span>
                </div>
              )
            }
            const hasCritical = tool.counts.critical > 0
            const hasHigh = tool.counts.high > 0
            const hasSevere = hasCritical || hasHigh
            return (
              <Link
                key={tool.label}
                href={tool.href}
                className={`group relative rounded-2xl border bg-[var(--color-surface)] px-4 py-3.5 transition-colors hover:bg-[var(--color-bg-hover)] ${LINK_FOCUS} ${
                  hasCritical ? "border-[var(--color-severity-critical)]/20" : hasHigh ? "border-[var(--color-severity-high)]/15" : "border-[var(--color-border)]"
                }`}
              >
                <div className="flex items-center gap-3">
                  <svg className="h-5 w-5 shrink-0 text-[var(--color-text-secondary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round"><path d={tool.icon} /></svg>
                  <span className="text-sm font-semibold text-[var(--color-text-primary)]">{tool.label}</span>
                  <span className="ml-auto flex items-center gap-2.5">
                    {trend.length >= 2 && tool.counts.total > 0 && (
                      <MiniSparkline
                        points={trend.slice(-7).map(p => p.total)}
                        color={hasCritical ? SEV_VARS.critical : hasHigh ? SEV_VARS.high : "var(--color-text-tertiary)"}
                      />
                    )}
                    <span className={`text-lg font-bold tabular-nums leading-none ${hasCritical ? SEV_CLASSES.critical.text : hasHigh ? SEV_CLASSES.high.text : "text-[var(--color-text-primary)]"}`}>
                      {tool.counts.total.toLocaleString()}
                    </span>
                    <svg className="h-4 w-4 text-[var(--color-text-tertiary)] transition-transform group-hover:translate-x-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M9 18l6-6-6-6" /></svg>
                  </span>
                </div>
                {tool.counts.total > 0 ? (
                  <div className="mt-2.5 flex items-center gap-3">
                    <div className="flex h-1.5 flex-1 overflow-hidden rounded-full bg-[var(--color-surface-raised)]"
                      role="img" aria-label={`${tool.counts.critical} critical, ${tool.counts.high} high, ${tool.counts.medium} medium, ${tool.counts.low} low`}
                    >
                      {tool.counts.critical > 0 && <span className="h-full" style={{ width: `${(tool.counts.critical / tool.counts.total) * 100}%`, background: SEV_VARS.critical }} />}
                      {tool.counts.high > 0 && <span className="h-full" style={{ width: `${(tool.counts.high / tool.counts.total) * 100}%`, background: SEV_VARS.high }} />}
                      {tool.counts.medium > 0 && <span className="h-full" style={{ width: `${(tool.counts.medium / tool.counts.total) * 100}%`, background: SEV_VARS.medium }} />}
                      {tool.counts.low > 0 && <span className="h-full" style={{ width: `${(tool.counts.low / tool.counts.total) * 100}%`, background: SEV_VARS.low }} />}
                    </div>
                    <span className="text-[11px] tabular-nums text-[var(--color-text-tertiary)]">
                      {hasCritical && <span className={SEV_CLASSES.critical.text}>{tool.counts.critical} crit</span>}
                      {hasCritical && hasHigh && <span> · </span>}
                      {hasHigh && <span className={SEV_CLASSES.high.text}>{tool.counts.high} high</span>}
                    </span>
                  </div>
                ) : (
                  <p className="mt-2 text-xs text-[var(--color-text-tertiary)]">
                    {sourcesState === "ok" && sources.length > 0 ? "No findings yet" : sourcesState === "ok" ? "Not configured" : "No data"}
                  </p>
                )}
              </Link>
            )
          })}
        </div>
      </div>

      {/* Sources */}
      {sources.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-3">
            <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">Sources</p>
            <div className="flex items-center gap-3 text-xs text-[var(--color-text-secondary)]">
              {healthySources > 0 && (
                <span className="flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-status-ok)]" aria-hidden="true" />
                  {healthySources} healthy
                </span>
              )}
              {issueSources > 0 && (
                <span className="flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-severity-critical)]" aria-hidden="true" />
                  <span className="text-[var(--color-severity-critical)]">{issueSources} need attention</span>
                </span>
              )}
            </div>
          </div>
          <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] divide-y divide-[var(--color-border)]">
            {sources.map(src => {
              const statusCfg: Record<string, { dot: string; label: string }> = {
                connected: { dot: "bg-[var(--color-status-ok)]", label: "Connected" },
                syncing: { dot: "bg-[var(--color-severity-medium)] motion-safe:animate-pulse", label: "Syncing" },
                error: { dot: "bg-[var(--color-severity-critical)]", label: "Error" },
                disconnected: { dot: "bg-[var(--color-severity-critical)]", label: "Disconnected" },
                "not-synced": { dot: "bg-[var(--color-text-tertiary)]", label: "Not synced" },
              }
              const cfg = statusCfg[src.status] ?? statusCfg["not-synced"]
              const displayName = src.name || src.auth?.orgOrOwner || src.auth?.username || src.sourceType
              return (
                <Link
                  key={src.id}
                  href={`/sources/${src.category}/${src.id}`}
                  className={`flex items-center gap-4 px-5 py-3 transition-colors hover:bg-[var(--color-bg-hover)] ${LINK_FOCUS}`}
                >
                  <span className="min-w-[120px] text-sm font-medium text-[var(--color-text-primary)] truncate">{displayName}</span>
                  <span className="text-xs text-[var(--color-text-secondary)] flex-1">{src.sourceType}</span>
                  {src.discoveredItemCount != null && src.discoveredItemCount > 0 && (
                    <span className="text-xs tabular-nums text-[var(--color-text-secondary)]">{src.discoveredItemCount} items</span>
                  )}
                  <span className="flex items-center gap-1.5 shrink-0">
                    <span className={`h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
                    <span className="text-xs text-[var(--color-text-secondary)]">{cfg.label}</span>
                  </span>
                </Link>
              )
            })}
          </div>
        </div>
      )}

      {/* Empty state */}
      {sources.length === 0 && sourcesState === "ok" && (
        <div className="rounded-2xl border border-dashed border-[var(--color-border)] bg-[var(--color-surface)] p-8 text-center">
          <p className="text-sm font-medium text-[var(--color-text-primary)]">No sources connected</p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            Connect a Git repository or container registry to start scanning.
          </p>
          <div className="mt-4 flex justify-center gap-3">
            <Link href="/sources/code-repositories" className={`rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm font-semibold text-[var(--color-text-primary)] transition-colors hover:bg-[var(--color-surface-raised)] ${LINK_FOCUS}`}>
              Add Git Repository
            </Link>
            <Link href="/sources/container-registry" className={`rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm font-semibold text-[var(--color-text-primary)] transition-colors hover:bg-[var(--color-surface-raised)] ${LINK_FOCUS}`}>
              Add Container Registry
            </Link>
          </div>
        </div>
      )}
    </div>
  )
}
