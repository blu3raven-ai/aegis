import { redirect } from "next/navigation"
import { requirePermission } from "@/lib/server/auth/server"
import { IntegrationsContent } from "@/app/(app)/operations/IntegrationsContent"

export default async function IntegrationsSettingsPage() {
  const userOrResponse = await requirePermission("view_settings")
  if (userOrResponse instanceof Response) redirect("/settings/account")
  return <IntegrationsContent />
}
