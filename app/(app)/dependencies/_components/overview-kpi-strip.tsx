import type { AnalyticsPayload } from "@/lib/shared/dashboard-analytics"
import type { OpenFindingsFilterOpts } from "@/lib/shared/dependencies/utils"
import { KpiCard } from "@/components/shared/KpiCard"

export function OverviewKpiStrip({
  analytics,
  staleCount,
  deferredCount = 0,
  onOpenFindingsFiltered,
}: {
  analytics: AnalyticsPayload | null
  staleCount: number
  deferredCount?: number
  onOpenFindingsFiltered?: (opts: OpenFindingsFilterOpts) => void
}) {
  const total    = analytics?.counts.total    ?? 0
  const critical = analytics?.counts.critical ?? 0
  const high     = analytics?.counts.high     ?? 0
  const urgent   = critical + high
  const fixed30d = analytics?.remediation.fixedLast30d ?? 0

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
      <KpiCard
        label="Open Findings"
        value={String(total)}
        note="Total open (deduplicated)"
        valueClass="text-[var(--color-text-primary)]"
        onClick={() => onOpenFindingsFiltered?.({ state: "open" })}
      />
      <KpiCard
        label="Urgent"
        value={String(urgent)}
        note="Critical + High open"
        valueClass="text-red-400"
        onClick={() => onOpenFindingsFiltered?.({ severity: ["critical", "high"] })}
      />
      <KpiCard
        label="Deferred"
        value={String(deferredCount)}
        note="No patch available yet"
        valueClass="text-orange-400"
        onClick={() => onOpenFindingsFiltered?.({ state: "deferred" })}
      />
      <KpiCard
        label="Stale (>30d)"
        value={String(staleCount)}
        note="Open and unpatched >30 days"
        valueClass="text-amber-400"
        onClick={() => onOpenFindingsFiltered?.({ state: "open", ageBucket: "30d+" })}
      />
      <KpiCard
        label="Fixed Recently"
        value={String(fixed30d)}
        note="Closed in last 30 days"
        valueClass="text-emerald-400"
        onClick={() => onOpenFindingsFiltered?.({ state: "fixed" })}
      />
    </div>
  )
}
