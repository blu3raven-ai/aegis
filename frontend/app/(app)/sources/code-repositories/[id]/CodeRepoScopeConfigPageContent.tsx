"use client"

import { use } from "react"
import { useHasPermission } from "@/lib/client/use-permission"
import { ScopeConfigContent } from "@/app/(app)/settings/sources/_components/ScopeConfigContent"

export function CodeRepoScopeConfigPageContent({ params }: { params: Promise<{ id: string }> }) {
  const { allowed: canEdit } = useHasPermission("manage_settings")
  const { id } = use(params)

  return (
    <main className="mx-auto max-w-5xl p-6 lg:p-10">
      <ScopeConfigContent category="code-repositories" connectionId={id} canEdit={canEdit} basePath="/sources/code-repositories" />
    </main>
  )
}
