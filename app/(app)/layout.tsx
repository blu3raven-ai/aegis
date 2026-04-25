import { redirect } from "next/navigation"
import { getSession } from "@/lib/server/session"
import { getSettingsServer, fetchPolicyServer } from "@/lib/server/settings-api"
import { AppShell } from "./AppShell"

export const dynamic = "force-dynamic"

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const session = await getSession()
  if (!session) redirect("/login")

  const [settingsResult, policy] = await Promise.all([
    getSettingsServer({ id: session.userId, role: session.role, roleId: session.roleId }),
    fetchPolicyServer({ id: session.userId, role: session.role, roleId: session.roleId }),
  ])

  const tools = settingsResult.ok ? settingsResult.data.tools : null

  const sidebarProps = {
    dependenciesEnabled: tools?.dependencies?.enabled ?? false,
    containerScanningEnabled: tools?.containerScanning?.enabled ?? false,
    secretsEnabled: tools?.secrets.enabled ?? false,
    codeScanningEnabled: tools?.codeScanning.enabled ?? false,
    iacEnabled: tools?.iacSecurity?.enabled ?? false,
    policy: policy as any,
  }

  return (
    <AppShell sidebarProps={sidebarProps}>
      {children}
    </AppShell>
  )
}
