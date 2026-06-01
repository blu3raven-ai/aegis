"use client"

import type { GqlCodeScanningAnalytics } from "@/lib/shared/graphql/types"
import { KpiCard } from "@/components/shared/KpiCard"
import { MetricCard, formatDays, formatCount } from "@/components/shared/MetricCard"

export interface CodeScanningOverviewFilter {
  severity?: string
  state?: string
  ruleId?: string
  repo?: string
  ageBucket?: string
}

interface Props {
  analytics: GqlCodeScanningAnalytics | null
  onGoToFindings: (opts: CodeScanningOverviewFilter) => void
}

const SEV_COLOUR: Record<string, string> = {
  critical: "text-[var(--color-severity-critical)]",
  high: "text-[var(--color-severity-high)]",
  medium: "text-[var(--color-severity-medium)]",
  low: "text-[var(--color-severity-low)]",
}

const AGE_BUCKETS = [
  { label: "< 7d", key: "0-7d", colour: "bg-[var(--color-status-ok)]" },
  { label: "7–30d", key: "8-30d", colour: "bg-[var(--color-severity-medium)]" },
  { label: "30–90d", key: "31-90d", colour: "bg-[var(--color-severity-high)]" },
  { label: "90d+", key: "90d+", colour: "bg-[var(--color-severity-critical)]" },
]

export function CodeScanningOverviewTab({ analytics, onGoToFindings }: Props) {
  const counts = analytics?.counts ?? { total: 0, critical: 0, high: 0, medium: 0, low: 0 }
  const topRules = analytics?.topRules ?? []
  const ageBuckets = analytics?.ageBuckets ?? []
  const remediation = analytics?.remediation
  const coverage = analytics?.repositoryCoverage

  const openCount = counts.total
  const urgent = counts.critical + counts.high
  const staleCount = (() => {
    const bucket = ageBuckets.find((b) => b.label === "30d+")
    return bucket?.count ?? 0
  })()
  const awaitingCount = analytics?.awaitingFixCount ?? 0
  const fixed30d = remediation?.fixedLast30d ?? 0

  return (
    <div className="space-y-5">

      {/* ── 1. KPI strip ──────────────────────────────────────────────────── */}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <KpiCard label="Open findings" value={String(counts.total)} note="Total open" valueClass="text-[var(--color-text-primary)]" onClick={() => onGoToFindings({ state: "open" })} />
        <KpiCard label="Urgent" value={String(urgent)} note="Critical + High open" valueClass="text-[var(--color-severity-critical)]" onClick={() => onGoToFindings({ severity: "critical" })} />
        <KpiCard label="Awaiting fix" value={String(awaitingCount)} note="Fix in progress" valueClass="text-[var(--color-severity-high)]" onClick={() => onGoToFindings({ state: "awaiting_fix" })} />
        <KpiCard label="Stale (>30d)" value={String(staleCount)} note="Open and unpatched >30 days" valueClass="text-[var(--color-severity-medium)]" onClick={() => onGoToFindings({ state: "open", ageBucket: "30d+" })} />
        <KpiCard label="Fixed recently" value={String(fixed30d)} note="Closed in last 30 days" valueClass="text-[var(--color-state-fixed)]" onClick={() => onGoToFindings({ state: "fixed" })} />
      </div>

      {/* ── 2. Attention strip — 3 contextual cards ────────────────────── */}
      <div className="grid gap-4 xl:grid-cols-3">

        {/* Backlog Age */}
        <Card eyebrow="Backlog Age" title="Age Breakdown" subtitle={`${openCount} open findings — how long have they been sitting?`}>
          {openCount === 0 ? (
            <p className="text-sm text-[var(--color-state-fixed)]">No open findings at this time.</p>
          ) : (
            <div className="space-y-2">
              {AGE_BUCKETS.map((b) => {
                const bucket = ageBuckets.find((ab) => ab.label === b.key)
                const count = bucket?.count ?? 0
                const pct = openCount > 0 ? Math.round((count / openCount) * 100) : 0
                return (
                  <button
                    key={b.key}
                    type="button"
                    disabled={count === 0}
                    onClick={() => count > 0 && onGoToFindings({ state: "open", ageBucket: b.label })}
                    className={`flex w-full items-center gap-3 rounded-lg px-1 py-0.5 text-left transition-colors ${count > 0 ? "cursor-pointer hover:bg-[var(--color-surface-raised)]" : "cursor-default"}`}
                  >
                    <span className="w-14 shrink-0 text-right text-[11px] text-[var(--color-text-secondary)]">{b.label}</span>
                    <div className="flex-1 overflow-hidden rounded-full bg-[var(--color-border)]" style={{ height: 8 }}>
                      <div className={`h-full rounded-full ${b.colour} transition-all`} style={{ width: `${pct}%` }} />
                    </div>
                    <span className={`w-6 text-right text-xs font-semibold tabular-nums ${count > 0 ? "text-[var(--color-text-primary)]" : "text-[var(--color-text-secondary)]"}`}>{count}</span>
                  </button>
                )
              })}
            </div>
          )}
          <LinkButton label={`${openCount} open findings`} sublabel="View all in Findings →" onClick={() => onGoToFindings({ state: "open" })} />
        </Card>

        {/* Triage Signal — Top Rules */}
        <Card eyebrow="Triage Signal" title="Top Triggered Rules" subtitle="Click a rule to filter findings by that rule.">
          {topRules.length === 0 ? (
            <p className="text-sm text-[var(--color-text-secondary)]">No rule data yet.</p>
          ) : (
            <div className="space-y-2">
              {topRules.slice(0, 5).map((rule) => (
                <button
                  key={rule.ruleId}
                  type="button"
                  onClick={() => onGoToFindings({ ruleId: rule.ruleId })}
                  className="flex w-full items-center justify-between gap-3 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3 text-left transition-colors hover:border-[var(--color-accent-border)]"
                >
                  <span className="min-w-0">
                    <span className="block truncate text-sm font-semibold text-[var(--color-text-primary)]">
                      {rule.ruleId.split(".").slice(-2).join(".")}
                    </span>
                    <span className="text-xs text-[var(--color-text-secondary)]">{rule.count} findings</span>
                  </span>
                  <span className="shrink-0 rounded-full bg-[var(--color-severity-high-subtle)] px-2.5 py-1 text-xs font-bold tabular-nums text-[var(--color-severity-high)]">
                    {counts.total > 0 ? `${Math.round((rule.count / counts.total) * 100)}%` : "0%"}
                  </span>
                </button>
              ))}
            </div>
          )}
          <LinkButton label="All findings" sublabel="View all in Findings →" onClick={() => onGoToFindings({ state: "" })} />
        </Card>

        {/* Review Focus — Severity breakdown */}
        <div className="flex flex-col rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
          <div className="mb-4 flex items-center justify-between gap-3">
            <h3 className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">
              Review Focus
            </h3>
            <button
              type="button"
              onClick={() => onGoToFindings({ state: "open" })}
              className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-1 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)]"
            >
              {counts.total} open
            </button>
          </div>
          <div className="h-3 overflow-hidden rounded-full bg-[var(--color-border)]">
            <div className="flex h-full">
              {counts.total > 0 && (
                <>
                  <div className="bg-[var(--color-severity-critical)]" style={{ width: `${(counts.critical / counts.total) * 100}%` }} />
                  <div className="bg-[var(--color-severity-high)]" style={{ width: `${(counts.high / counts.total) * 100}%` }} />
                  <div className="bg-[var(--color-severity-medium)]" style={{ width: `${(counts.medium / counts.total) * 100}%` }} />
                  <div className="bg-[var(--color-severity-low)]" style={{ width: `${(counts.low / counts.total) * 100}%` }} />
                </>
              )}
            </div>
          </div>
          <div className="mt-4 space-y-2">
            {(["critical", "high", "medium", "low"] as const).map((sev) => {
              const count = counts[sev]
              const pct = counts.total > 0 ? Math.round((count / counts.total) * 100) : 0
              const tones: Record<string, string> = { critical: "bg-[var(--color-severity-critical)]", high: "bg-[var(--color-severity-high)]", medium: "bg-[var(--color-severity-medium)]", low: "bg-[var(--color-severity-low)]" }
              const notes: Record<string, string> = { critical: "Could cause serious impact", high: "Needs attention soon", medium: "Plan into upcoming work", low: "Lower business impact" }
              return (
                <button
                  key={sev}
                  type="button"
                  onClick={() => onGoToFindings({ severity: sev })}
                  className="w-full text-left transition-colors"
                >
                  <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-3">
                    <div className="mb-2 flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2">
                        <span className={`h-2.5 w-2.5 rounded-full ${tones[sev]}`} />
                        <span className="text-sm font-medium capitalize text-[var(--color-text-primary)]">{sev}</span>
                      </div>
                      <span className="text-sm text-[var(--color-text-secondary)]">{pct}%</span>
                    </div>
                    <div className="h-2.5 rounded-full bg-[var(--color-surface-raised)]">
                      <div className={`h-2.5 rounded-full ${tones[sev]}`} style={{ width: `${Math.max(pct, pct ? 6 : 0)}%` }} />
                    </div>
                    <div className="mt-2 flex items-center justify-between text-xs text-[var(--color-text-secondary)]">
                      <span>{count} issues</span>
                      <span>{notes[sev]}</span>
                    </div>
                  </div>
                </button>
              )
            })}
          </div>
          <button
            type="button"
            onClick={() => onGoToFindings({ state: "dismissed" })}
            className="mt-5 flex w-full items-center justify-between rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3 text-left transition-colors hover:border-[var(--color-accent-border)]"
          >
            <span className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
              View dismissed findings
            </span>
            <span className="text-xs text-[var(--color-accent)]">→</span>
          </button>
        </div>
      </div>

      {/* ── 3. Stats strip — Reach + Delivery ─────────────────────────── */}
      <div className="grid gap-5 xl:grid-cols-2">

        {/* Reach */}
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
          <p className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">Reach</p>
          <h3 className="mt-2 text-base font-semibold text-[var(--color-text-primary)]">Repositories Affected</h3>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">How widely the current open issues are spread across the organization.</p>
          <div className="mt-4 rounded-2xl bg-[var(--color-surface-raised)] p-4">
            <p className="text-2xl font-semibold leading-none tabular-nums text-[var(--color-text-primary)]">{coverage?.percentage ?? 0}%</p>
            <p className="mt-1 text-sm text-[var(--color-text-secondary)]">of active repositories affected</p>
            <div className="mt-4 h-3 overflow-hidden rounded-full bg-[var(--color-border)]">
              <div className="h-full bg-[var(--color-accent)]" style={{ width: `${coverage?.percentage ?? 0}%` }} />
            </div>
            <div className="mt-4 grid grid-cols-2 gap-3">
              <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-3">
                <p className="text-sm text-[var(--color-text-secondary)]">Affected</p>
                <p className="mt-1 text-2xl font-semibold text-[var(--color-text-primary)]">{formatCount(coverage?.affected)}</p>
              </div>
              <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-3">
                <p className="text-sm text-[var(--color-text-secondary)]">Unaffected</p>
                <p className="mt-1 text-2xl font-semibold text-[var(--color-text-primary)]">{formatCount(coverage?.unaffected)}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Delivery */}
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
          <p className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">Delivery</p>
          <h3 className="mt-2 text-base font-semibold text-[var(--color-text-primary)]">How Fast Issues Are Being Closed</h3>
          <div className="mt-5 grid grid-cols-2 gap-3">
            <MetricCard label="Typical fix time" value={formatDays(remediation?.medianDays)} />
            <MetricCard label="Average fix time" value={formatDays(remediation?.avgDays)} />
            <MetricCard label="Closed last 30 days" value={formatCount(remediation?.fixedLast30d)} />
            <MetricCard label="Total resolved (trend basis)" value={formatCount(remediation?.totalFixed)} />
          </div>
        </div>
      </div>

    </div>
  )
}


// ── Sub-components ──────────────────────────────────────────────────────────


function Card({ eyebrow, title, subtitle, children }: { eyebrow: string; title: string; subtitle: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
      <p className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">{eyebrow}</p>
      {title && <h3 className="mt-2 text-base font-semibold text-[var(--color-text-primary)]">{title}</h3>}
      {subtitle && <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">{subtitle}</p>}
      <div className="mt-4 flex-1">{children}</div>
    </div>
  )
}

function LinkButton({ label, sublabel, onClick }: { label: string; sublabel: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="mt-5 flex w-full items-center justify-between rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3 text-left transition-colors hover:border-[var(--color-accent-border)]"
    >
      <span>
        <span className="block text-sm font-semibold text-[var(--color-text-primary)]">{label}</span>
        {sublabel && <span className="text-sm font-medium text-[var(--color-accent)] hover:underline">{sublabel}</span>}
      </span>
    </button>
  )
}

