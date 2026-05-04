import { redirect } from "next/navigation"
import { requirePermission } from "@/lib/server/auth/server"
import { can } from "@/lib/shared/auth/roles"
import { ScopeConfigContent } from "@/app/(app)/settings/sources/_components/ScopeConfigContent"

export default async function ContainerRegistryScopeConfigPage({ params }: { params: Promise<{ id: string }> }) {
  const userOrResponse = await requirePermission("view_settings")
  if (userOrResponse instanceof Response) redirect("/")
  const canEdit = can(userOrResponse.role, "manage_settings")
  const { id } = await params
  return (
    <main className="mx-auto max-w-5xl p-6 lg:p-10">
      <ScopeConfigContent category="container-registry" connectionId={id} canEdit={canEdit} basePath="/sources/container-registry" />
    </main>
  )
}
