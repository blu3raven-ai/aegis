"use client"

import { ToolRefreshControls } from "@/components/shared/ToolRefreshControls"
import { fetchCodeScanningRuns, startCodeScanningRuns, cancelCodeScanningRuns } from "@/lib/client/code-scanning-client"

export function CodeScanningRefreshControls({ org, orgLabel }: { org: string; orgLabel?: string }) {
  return (
    <ToolRefreshControls
      org={org}
      orgLabel={orgLabel}
      eventKey="code_scanning"
      toolLabel="Code scanning"
      fetchRuns={fetchCodeScanningRuns}
      startRuns={(q, mode) =>
        startCodeScanningRuns(q, mode as "full" | "rules_only" | "ai_review_only" | undefined)
      }
      cancelRuns={cancelCodeScanningRuns}
      modeOptions={[
        { id: "rules_only", label: "Rules Scan Only", description: "Run rule-based scan without AI classification" },
        { id: "ai_review_only", label: "AI Review Only", description: "Run AI classification on existing unreviewed findings" },
      ]}
    />
  )
}
