import { KpiCard } from "@/components/shared/KpiCard"

export interface SecretsOverviewFilterOpts {
  status?: string
  repo?: string
  ageBucket?: string
}

export function SecretsOverviewKpiStrip({
  uniqueKeyCount,
  funnel,
  staleCount,
  resolvedRecentlyCount,
  onOpenReviewFiltered,
}: {
  uniqueKeyCount: number
  funnel: {
    newCount: number
    confirmedCount: number
    falsePositiveCount: number
    actionTakenCount: number
  }
  staleCount: number
  resolvedRecentlyCount: number
  onOpenReviewFiltered: (opts: SecretsOverviewFilterOpts) => void
}) {
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
      <KpiCard
        label="Unique Keys"
        value={String(uniqueKeyCount)}
        note="Total deduplicated secrets"
        valueClass="text-[var(--color-text-primary)]"
        onClick={() => onOpenReviewFiltered({})}
      />
      <KpiCard
        label="Confirmed"
        value={String(funnel.confirmedCount)}
        note="Verified real, needs rotation"
        valueClass="text-[var(--color-severity-critical)]"
        onClick={() => onOpenReviewFiltered({ status: "confirmed" })}
      />
      <KpiCard
        label="New"
        value={String(funnel.newCount)}
        note="Awaiting triage"
        valueClass="text-[var(--color-severity-high)]"
        onClick={() => onOpenReviewFiltered({ status: "new" })}
      />
      <KpiCard
        label="Stale (>30d)"
        value={String(staleCount)}
        note="Confirmed and unresolved >30 days"
        valueClass="text-[var(--color-severity-medium)]"
        onClick={() => onOpenReviewFiltered({ status: "confirmed", ageBucket: "30d+" })}
      />
      <KpiCard
        label="Resolved Recently"
        value={String(resolvedRecentlyCount)}
        note="Action taken in last 30 days"
        valueClass="text-[var(--color-status-ok)]"
        onClick={() => onOpenReviewFiltered({ status: "action_taken" })}
      />
    </div>
  )
}
