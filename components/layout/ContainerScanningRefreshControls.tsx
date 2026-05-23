"use client"

import { useCallback, useState } from "react"
import { ToolRefreshControls } from "@/components/shared/ToolRefreshControls"
import { fetchContainerScanningRuns, startContainerScanningRuns, cancelContainerScanningRuns } from "@/lib/client/container-scanning-client"

export function ContainerScanningRefreshControls({ org, orgLabel }: { org: string; orgLabel?: string }) {
  const [hasSboms, setHasSboms] = useState(true)

  const wrappedFetchRuns = useCallback(async (orgQuery: string) => {
    const result = await fetchContainerScanningRuns(orgQuery)
    if (result.payload.hasSboms !== undefined) setHasSboms(result.payload.hasSboms)
    return result
  }, [])

  return (
    <ToolRefreshControls
      org={org}
      orgLabel={orgLabel}
      eventKey="container-scanning"
      toolLabel="Container scan"
      fetchRuns={wrappedFetchRuns}
      startRuns={(q, mode) => startContainerScanningRuns(q, undefined, mode as "full" | "sbom_only" | "advisories_only" | undefined)}
      cancelRuns={cancelContainerScanningRuns}
      modeOptions={[
        { id: "sbom_only", label: "Update SBOMs", description: "Re-scan images, generate fresh SBOMs" },
        {
          id: "advisories_only",
          label: "Update Advisories",
          description: "Re-match stored SBOMs against latest vulnerability DBs",
          disabled: !hasSboms,
          disabledReason: "No stored SBOMs — run a full scan first",
        },
      ]}
    />
  )
}
