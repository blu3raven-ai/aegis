import { DependenciesDashboardView } from "@/app/(app)/dependencies/_components/dependencies-dashboard-view"
import { PageHeader } from "@/components/layout/PageHeader"
import { DependenciesRefreshControls } from "@/components/layout/DependenciesRefreshControls"
import { getToolEnabledOrgs } from "@/lib/server/tool-orgs"
import { getSession } from "@/lib/server/session"
import { checkToolPrerequisites } from "@/lib/server/settings-api"
import { can } from "@/lib/shared/auth/roles"
import { redirect } from "next/navigation"

export const metadata = { title: "Dependency Scanning (SCA)" }

export default async function DependenciesDashboardPage({
  searchParams,
}: {
  searchParams: Promise<{ tab?: string }>
}) {
  const session = await getSession()
  if (!session) redirect("/login")

  const { tab } = await searchParams
  const orgs = await getToolEnabledOrgs("dependencies")
  const hasOrgs = orgs.length > 0
  const orgLabel = hasOrgs ? orgs.join(", ") : "No organisations configured"
  const orgQuery = orgs.join(",")
  const canEdit = can(session.role, "manage_settings")
  const { ready: scannerReady } = hasOrgs
    ? await checkToolPrerequisites("dependencies", { id: session.userId, role: session.role, roleId: session.roleId })
    : { ready: false }
  const prerequisitesMet = hasOrgs && scannerReady
  const initialTab = tab ?? (!prerequisitesMet ? "settings" : "overview")

  return (
    <>
      <PageHeader
        icon={<ShieldIcon />}
        title="Dependency Scanning"
        description="Scans your project dependencies for known vulnerabilities and tracks remediation"
        controls={<DependenciesRefreshControls org={orgQuery} orgLabel={orgLabel} />}
      />

      <main className="flex-1 max-w-7xl mx-auto w-full px-6 py-8">
        <DependenciesDashboardView org={orgQuery} initialTab={initialTab} canEdit={canEdit} prerequisitesMet={prerequisitesMet} />
      </main>
    </>
  )
}

function ShieldIcon() {
  return (
    <div className="p-1.5 bg-blue-50 dark:bg-blue-950 rounded-lg">
      <svg
        xmlns="http://www.w3.org/2000/svg"
        className="w-5 h-5 text-blue-500"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        strokeWidth={2}
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z"
        />
      </svg>
    </div>
  )
}
