import { redirect } from "next/navigation"
import { requirePermission } from "@/lib/server/auth/server"
import { FleetContent } from "@/app/(app)/fleet/FleetContent"

export default async function FleetSettingsPage() {
  const userOrResponse = await requirePermission("view_settings")
  if (userOrResponse instanceof Response) redirect("/settings/account")
  return <FleetContent />
}
