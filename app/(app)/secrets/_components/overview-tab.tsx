import { SecretsOverviewKpiStrip, type SecretsOverviewFilterOpts } from "@/app/(app)/secrets/_components/overview-kpi-strip"
import { OverviewAttentionStrip } from "@/app/(app)/secrets/_components/overview-attention-strip"
import { SecretsOverviewStatsPanel } from "@/app/(app)/secrets/_components/overview-stats-panel"
import type { GqlAgeBucket, GqlSecretsRepoPriority } from "@/lib/shared/graphql/types"

export function OverviewTab({
  uniqueKeyCount,
  funnel,
  staleCount,
  resolvedRecentlyCount,
  unresolvedCount,
  ageBuckets,
  triagePriority,
  remediation,
  repositoryCoverage,
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
  unresolvedCount: number
  ageBuckets: GqlAgeBucket[]
  triagePriority: GqlSecretsRepoPriority[]
  remediation?: {
    medianDays: number | null
    avgDays: number | null
    fixedLast30d: number
    totalFixed: number
  }
  repositoryCoverage?: {
    percentage: number
    affected: number
    unaffected: number
  }
  onOpenReviewFiltered: (opts: SecretsOverviewFilterOpts) => void
}) {
  return (
    <div className="space-y-5">
      <SecretsOverviewKpiStrip
        uniqueKeyCount={uniqueKeyCount}
        funnel={funnel}
        staleCount={staleCount}
        resolvedRecentlyCount={resolvedRecentlyCount}
        onOpenReviewFiltered={onOpenReviewFiltered}
      />
      <OverviewAttentionStrip
        unresolvedCount={unresolvedCount}
        ageBuckets={ageBuckets}
        triagePriority={triagePriority}
        funnel={funnel}
        onOpenReviewFiltered={onOpenReviewFiltered}
      />
      <SecretsOverviewStatsPanel
        remediation={remediation}
        repositoryCoverage={repositoryCoverage}
      />
    </div>
  )
}
