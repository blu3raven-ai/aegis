import { redirect } from "next/navigation"
import { getSession } from "@/lib/server/session"
import { SecretsPageShell } from "./SecretsPageShell"
import { getToolEnabledOrgs } from "@/lib/server/tool-orgs"
import { checkToolPrerequisites } from "@/lib/server/settings-api"
import { can } from "@/lib/shared/auth/roles"

export default async function SecretsDashboardPage({
  searchParams,
}: {
  searchParams: Promise<{ tab?: string }>
}) {
  const session = await getSession()
  if (!session) redirect("/login")

  const { tab } = await searchParams
  const enabledOrgs = await getToolEnabledOrgs("secrets")
  const hasOrgs = enabledOrgs.length > 0
  const canEdit = can(session.role, "manage_settings")
  const { ready: scannerReady } = hasOrgs
    ? await checkToolPrerequisites("secrets", { id: session.userId, role: session.role, roleId: session.roleId })
    : { ready: false }
  const prerequisitesMet = hasOrgs && scannerReady
  const initialTab = tab ?? (!prerequisitesMet ? "settings" : "overview")

  return <SecretsPageShell orgs={enabledOrgs} initialTab={initialTab} canEdit={canEdit} prerequisitesMet={prerequisitesMet} />
}
