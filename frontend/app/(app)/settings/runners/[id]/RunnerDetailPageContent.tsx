"use client"

import { use } from "react"
import { useHasPermission } from "@/lib/client/use-permission"
import { RunnerDetailContent } from "./RunnerDetailContent"

export function RunnerDetailPageContent({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { allowed: canEdit } = useHasPermission("manage_runners")
  const { id } = use(params)

  return (
    <div className="mx-auto max-w-5xl p-6 lg:p-10">
      <RunnerDetailContent runnerId={id} canEdit={canEdit} />
    </div>
  )
}
