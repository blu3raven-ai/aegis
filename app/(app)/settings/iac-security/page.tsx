import { redirect } from "next/navigation"
import { requirePermission } from "@/lib/server/auth/server"
import { IacSecurityContent } from "./IacSecurityContent"

export default async function IacSecuritySettingsPage() {
  const userOrResponse = await requirePermission("manage_settings")
  if (userOrResponse instanceof Response) {
    redirect("/settings/account")
  }

  return (
    <div className="mx-auto max-w-5xl p-6 lg:p-10">
      <IacSecurityContent />
    </div>
  )
}
