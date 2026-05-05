import type { OpenFindingsFilterOpts } from "@/lib/shared/dependencies/utils"
import type { GqlDependenciesAnalytics } from "@/lib/shared/graphql/types"
import { InsightsRiskConcentration } from "@/app/(app)/dependencies/_components/insights-risk-concentration"
import { InsightsImprovementTrend } from "@/app/(app)/dependencies/_components/insights-improvement-trend"
import { InsightsRemediationPriority } from "@/app/(app)/dependencies/_components/insights-remediation-priority"

export function DependenciesInsightsTab({
  analytics,
  onOpenFindingsFiltered,
}: {
  analytics: GqlDependenciesAnalytics | null
  onOpenFindingsFiltered: (opts: OpenFindingsFilterOpts) => void
}) {
  if (!analytics) {
    return (
      <div className="flex min-h-40 items-center justify-center text-sm text-[var(--color-text-secondary)]">
        Loading insights...
      </div>
    )
  }

  return (
    <div className="space-y-12">
      <InsightsRiskConcentration
        ecosystemBreakdown={analytics.ecosystemBreakdown}
        topVulnerablePackages={analytics.topVulnerablePackages}
        onOpenFindingsFiltered={onOpenFindingsFiltered}
      />
      <InsightsImprovementTrend
        monthlyTrend={analytics.monthlyTrend}
        mttrBySeverity={analytics.mttrBySeverity}
      />
      <InsightsRemediationPriority
        remediationPriority={analytics.remediationPriority}
        onOpenFindingsFiltered={onOpenFindingsFiltered}
      />
    </div>
  )
}
