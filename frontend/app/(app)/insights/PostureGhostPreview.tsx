/**
 * Dimmed ghost preview for Posture. Renders the same top-level shape as the
 * populated Summary tab (risk score hero + KPI grid + trend chart skeleton +
 * top repos), populated with placeholder values. Wrapper applies dimming and
 * aria-hidden, so this component renders the surfaces inline only.
 */

import { Card } from "@/components/ui/Card"

function RiskScoreHero() {
  return (
    <Card padding="lg" className="panel-ticks rounded-md">
      <div className="flex flex-wrap items-center gap-8">
        <div className="flex items-center gap-5">
          <div className="grid h-20 w-20 place-items-center rounded-full border-4 border-[var(--color-status-ok)]/40">
            <span className="text-2xl font-semibold tabular-nums text-[var(--color-text-primary)]">82</span>
          </div>
          <div>
            <p className="text-2xs font-mono font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">Risk score</p>
            <p className="mt-1 text-lg font-semibold tracking-tight text-[var(--color-text-primary)]">Healthy posture</p>
            <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">Calculated across all repositories</p>
          </div>
        </div>
        <div className="ml-auto grid grid-cols-2 gap-x-8 gap-y-2 text-xs text-[var(--color-text-secondary)]">
          <span>SLA compliance</span><span className="tabular-nums text-[var(--color-text-primary)]">94%</span>
          <span>MTTR (critical)</span><span className="tabular-nums text-[var(--color-text-primary)]">3.2d</span>
        </div>
      </div>
    </Card>
  )
}

function KpiGrid() {
  const items = [
    { label: "Open", value: "0", note: "across all scanners" },
    { label: "Critical", value: "0", note: "no criticals open" },
    { label: "High", value: "0", note: "no highs open" },
    { label: "Fixed", value: "0", note: "fixed in last 30d" },
  ]
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      {items.map((kpi) => (
        <Card key={kpi.label} padding="none" className="panel-ticks rounded-md px-5 py-3">
          <p className="text-[11px] font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">{kpi.label}</p>
          <p className="mt-2 text-2xl font-semibold leading-none tabular-nums text-[var(--color-text-primary)]">{kpi.value}</p>
          <p className="mt-2 text-[11px] text-[var(--color-text-tertiary)]">{kpi.note}</p>
        </Card>
      ))}
    </div>
  )
}

function TrendChart() {
  const w = 800
  const h = 140
  const padBottom = 18
  const usable = h - padBottom
  const points = [60, 58, 55, 62, 50, 48, 52, 45, 47, 40, 38, 42]
  const max = 70
  const slotW = w / (points.length - 1)
  const path = points
    .map((v, i) => `${i === 0 ? "M" : "L"} ${(slotW * i).toFixed(1)} ${(usable - (v / max) * usable).toFixed(1)}`)
    .join(" ")
  return (
    <Card className="rounded-md">
      <div className="mb-3 flex items-baseline justify-between">
        <h3 className="text-base font-semibold text-[var(--color-text-primary)]">Severity trend</h3>
        <span className="text-xs text-[var(--color-text-tertiary)]">last 30 days · preview</span>
      </div>
      <svg viewBox={`0 0 ${w} ${h}`} className="h-32 w-full" preserveAspectRatio="none">
        <g stroke="var(--color-border)" strokeWidth="1">
          <line x1="0" y1={usable * 0.33} x2={w} y2={usable * 0.33} strokeDasharray="2 4" />
          <line x1="0" y1={usable * 0.66} x2={w} y2={usable * 0.66} strokeDasharray="2 4" />
        </g>
        <path d={path} fill="none" stroke="var(--color-severity-high)" strokeWidth="2" />
      </svg>
    </Card>
  )
}

function AttentionPanel() {
  return (
    <Card className="rounded-md">
      <div className="mb-3 flex items-baseline justify-between">
        <h3 className="text-base font-semibold text-[var(--color-text-primary)]">Needs attention</h3>
        <span className="text-xs text-[var(--color-text-tertiary)]">preview</span>
      </div>
      <div className="space-y-2">
        {[1, 2, 3].map((n) => (
          <div key={n} className="flex items-center gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-2.5">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-[var(--color-severity-high)]" />
            <span className="flex-1 text-sm text-[var(--color-text-primary)]">Team {n} · example-org/service-{n}</span>
            <span className="text-xs tabular-nums text-[var(--color-text-tertiary)]">{4 - n} open</span>
          </div>
        ))}
      </div>
    </Card>
  )
}

export function PostureGhostPreview() {
  return (
    <div className="space-y-5 px-6 py-5">
      <RiskScoreHero />
      <KpiGrid />
      <TrendChart />
      <AttentionPanel />
    </div>
  )
}
