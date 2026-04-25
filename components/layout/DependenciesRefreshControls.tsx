"use client"

import { ToolRefreshControls } from "@/components/shared/ToolRefreshControls"
import { fetchDependenciesRuns, startDependenciesRuns, cancelDependenciesRuns } from "@/lib/client/dependencies-client"

export function DependenciesRefreshControls({ org, orgLabel }: { org: string; orgLabel?: string }) {
  return (
    <ToolRefreshControls
      org={org}
      orgLabel={orgLabel}
      eventKey="dependencies"
      toolLabel="Dependencies scan"
      fetchRuns={fetchDependenciesRuns}
      startRuns={(q, mode) => startDependenciesRuns(q, undefined, mode as "full" | "sbom_only" | "advisories_only" | undefined)}
      cancelRuns={cancelDependenciesRuns}
      modeOptions={[
        { id: "sbom_only", label: "Update SBOMs", description: "Re-scan repos, match against cached advisories" },
        { id: "advisories_only", label: "Update Advisories", description: "Pull latest advisories, re-match stored SBOMs" },
      ]}
    />
  )
}
