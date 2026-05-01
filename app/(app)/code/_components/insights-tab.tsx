"use client"

import type { GqlCodeScanningAnalytics } from "@/lib/shared/graphql/types"
import { InsightsExposureBreakdown } from "./insights-exposure-breakdown"
import { InsightsRiskConcentration } from "./insights-risk-concentration"
import { InsightsActionPriorities } from "./insights-action-priorities"

interface Props {
  analytics: GqlCodeScanningAnalytics | null
  onGoToFindings: (opts?: {
    severity?: string
    state?: string
    repo?: string
    ruleId?: string
    ageBucket?: string
  }) => void
}

export function CodeScanningInsightsTab({ analytics, onGoToFindings }: Props) {
  return (
    <div className="space-y-12">
      <InsightsExposureBreakdown
        analytics={analytics}
        onGoToFindings={(opts) => onGoToFindings(opts)}
      />
      <InsightsRiskConcentration
        analytics={analytics}
        onGoToFindings={(opts) => onGoToFindings(opts)}
      />
      <InsightsActionPriorities
        analytics={analytics}
        onGoToFindings={(opts) => onGoToFindings(opts)}
      />
    </div>
  )
}
