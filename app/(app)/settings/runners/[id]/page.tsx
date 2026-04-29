import { redirect } from "next/navigation"
import { requirePermission } from "@/lib/server/auth/server"
import { can } from "@/lib/shared/auth/roles"
import { RunnerDetailContent } from "./RunnerDetailContent"

export default async function RunnerDetailPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const userOrResponse = await requirePermission("view_settings")
  if (userOrResponse instanceof Response) redirect("/settings/account")
  const canEdit = can(userOrResponse.role, "manage_settings")
  const { id } = await params
  return (
    <div className="mx-auto max-w-5xl p-6 lg:p-10">
      <RunnerDetailContent runnerId={id} canEdit={canEdit} />
    </div>
  )
}
