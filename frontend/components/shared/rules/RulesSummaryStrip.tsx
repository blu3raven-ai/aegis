import { KpiCard } from "@/components/shared/KpiCard"
import type { RuleSummaryStats } from "@/lib/client/rules-api"

interface Props {
  stats: RuleSummaryStats | null
  loading: boolean
}

const NEUTRAL = "text-[var(--color-text-primary)]"
const POSITIVE = "text-[var(--color-state-fixed-text)]"
const WARN = "text-[var(--color-severity-medium-text)]"
const CRITICAL = "text-[var(--color-severity-critical-text)]"

function complianceClass(pct: number): string {
  if (pct >= 90) return POSITIVE
  if (pct >= 75) return WARN
  return CRITICAL
}

function countClass(n: number): string {
  if (n <= 0) return NEUTRAL
  return n >= 5 ? CRITICAL : WARN
}

export function RulesSummaryStrip({ stats, loading }: Props) {
  const unavailableNote = "Stats unavailable"
  const isEmpty = stats === null

  const activeRulesValue = isEmpty ? "—" : stats.active_rules.toLocaleString()
  const slaValue = isEmpty ? "—" : `${stats.sla_compliance_pct}%`
  const violationsValue = isEmpty ? "—" : stats.violations_open.toLocaleString()
  const coverageValue = isEmpty ? "—" : stats.coverage_gaps.toLocaleString()

  const fallbackNote = loading ? "Loading…" : unavailableNote

  // Strip sits inside the page body — no bg/border on the strip itself so it
  // doesn't visually glue to the PageHeader band above. KpiCard primitives
  // carry their own surface treatment. Mirrors the Compliance pattern.
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <KpiCard
        label="Active rules"
        value={activeRulesValue}
        note={isEmpty ? fallbackNote : "Currently enforced"}
        valueClass={NEUTRAL}
      />
      <KpiCard
        label="SLA compliance"
        value={slaValue}
        note={isEmpty ? fallbackNote : "Resolved within deadline (last 30d)"}
        valueClass={isEmpty ? NEUTRAL : complianceClass(stats.sla_compliance_pct)}
      />
      <KpiCard
        label="Violations open"
        value={violationsValue}
        note={isEmpty ? fallbackNote : "Past deadline"}
        valueClass={isEmpty ? NEUTRAL : countClass(stats.violations_open)}
      />
      <KpiCard
        label="Coverage gaps"
        value={coverageValue}
        note={isEmpty ? fallbackNote : "Repos missing required scanners"}
        valueClass={isEmpty ? NEUTRAL : countClass(stats.coverage_gaps)}
      />
    </div>
  )
}
