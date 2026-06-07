"use client"

import { use } from "react"
import { useSession } from "@/lib/client/use-session"
import { can } from "@/lib/shared/auth/roles"
import { ScopeConfigContent } from "@/app/(app)/settings/sources/_components/ScopeConfigContent"

export function ContainerImageScopeConfigContent({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { user } = useSession()
  const canEdit = user ? can(user.role as any, "manage_settings") : false
  const { id } = use(params)

  return (
    <div className="mx-auto max-w-5xl p-6 lg:p-10">
      <ScopeConfigContent connectionId={id} category="container-registry" canEdit={canEdit} />
    </div>
  )
}
