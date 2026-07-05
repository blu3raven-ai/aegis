"use client"

import { use } from "react"
import { useHasPermission } from "@/lib/client/use-permission"
import { ScopeConfigContent } from "@/app/(app)/settings/sources/_components/ScopeConfigContent"

export function ContainerRegistryScopeConfigPageContent({ params }: { params: Promise<{ id: string }> }) {
  const { allowed: canEdit } = useHasPermission("manage_settings")
  const { id } = use(params)

  return (
    <main className="mx-auto max-w-5xl p-6 lg:p-10">
      <ScopeConfigContent category="container-registry" connectionId={id} canEdit={canEdit} basePath="/sources/container-registry" />
    </main>
  )
}
