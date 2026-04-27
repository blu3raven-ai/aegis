import { redirect } from "next/navigation"
import { requireAuthenticatedUser } from "@/lib/server/auth/server"
import { can } from "@/lib/shared/auth/roles"
import { UsersSettingsForm } from "./UsersSettingsForm"

export default async function UsersSettingsPage() {
  const userOrResponse = await requireAuthenticatedUser()
  if (userOrResponse instanceof Response) {
    redirect("/login")
  }

  const canEdit = can(userOrResponse.role, "manage_users")
  return (
    <div className="mx-auto max-w-5xl p-6 lg:p-10">
      <UsersSettingsForm canEdit={canEdit} />
    </div>
  )
}
