"use client"

import { useCallback, useEffect, useState } from "react"
import { FleetSummary } from "@/components/shared/fleet/FleetSummary"
import { RunnersTable } from "@/components/shared/fleet/RunnersTable"
import { PageHeader } from "@/components/layout/PageHeader"
import { FleetIcon } from "@/lib/shared/ui/page-icons"
import { listRunners, type RunnerStatus } from "@/lib/client/fleet-api"

export function FleetContent() {
  const [runners, setRunners] = useState<RunnerStatus[]>([])

  const load = useCallback(async () => {
    try {
      const data = await listRunners()
      setRunners(data)
    } catch {
      // RunnersTable manages its own error state; summary silently shows 0s on failure
    }
  }, [])

  useEffect(() => { void load() }, [load])

  return (
    <div className="flex h-full flex-col overflow-y-auto bg-[var(--color-bg)]">
      <PageHeader
        icon={<FleetIcon />}
        title="Fleet"
        description="Runners and scanner pools across your infrastructure."
      />
      <div className="mx-auto w-full max-w-6xl space-y-5 p-6">
        <FleetSummary runners={runners} />
        <RunnersTable />
      </div>
    </div>
  )
}
