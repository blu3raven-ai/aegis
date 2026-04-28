import { redirect } from "next/navigation"
import { requirePermission } from "@/lib/server/auth/server"
import { can } from "@/lib/shared/auth/roles"
import { OrganisationsContent } from "./OrganisationsContent"

export default async function OrganisationsSettingsPage() {
  const userOrResponse = await requirePermission("view_settings")
  if (userOrResponse instanceof Response) {
    redirect("/settings/account")
  }

  const canEdit = can(userOrResponse.role, "manage_organisations")
  return (
    <div className="mx-auto max-w-5xl p-6 lg:p-10">
      <OrganisationsContent canEdit={canEdit} />
    </div>
  )
}
