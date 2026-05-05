import type { AnalyticsPayload } from "@/lib/shared/dashboard-analytics"
import type { GqlDependenciesAnalytics } from "@/lib/shared/graphql/types"
import type { OpenFindingsFilterOpts } from "@/lib/shared/dependencies/utils"
import { OverviewKpiStrip } from "@/app/(app)/dependencies/_components/overview-kpi-strip"
import { OverviewAttentionStrip } from "@/app/(app)/dependencies/_components/overview-attention-strip"
import { OverviewStatsPanel } from "@/app/(app)/dependencies/_components/overview-stats-panel"

export function DependenciesOverviewTab({
  analytics,
  activeSeverity,
  onOpenFindingsFiltered,
  onOpenHealth,
  entityLabel = "repo",
}: {
  analytics: GqlDependenciesAnalytics | null
  activeSeverity: string
  onOpenFindingsFiltered: (opts: OpenFindingsFilterOpts) => void
  onOpenHealth: () => void
  entityLabel?: "repo" | "image"
}) {
  const staleCount = analytics?.staleFindingsCount ?? 0
  const deferredCount = analytics?.deferredFindingsCount ?? 0

  // Sub-components still accept AnalyticsPayload; GqlDependenciesAnalytics is a
  // structural superset so a type assertion is safe here.
  const legacyAnalytics = analytics as unknown as AnalyticsPayload | null

  return (
    <div className="space-y-5">
      <OverviewKpiStrip analytics={legacyAnalytics} staleCount={staleCount} deferredCount={deferredCount} onOpenFindingsFiltered={onOpenFindingsFiltered} />
      <OverviewAttentionStrip
        analytics={analytics}
        activeSeverity={activeSeverity}
        onOpenFindingsFiltered={onOpenFindingsFiltered}
        entityLabel={entityLabel}
      />
      <OverviewStatsPanel analytics={legacyAnalytics} entityLabel={entityLabel} />
    </div>
  )
}
