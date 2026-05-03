import { ContainerScanningDashboardView } from "@/app/(app)/containers/_components/container-scanning-dashboard-view"
import { PageHeader } from "@/components/layout/PageHeader"
import { ContainerScanningRefreshControls } from "@/components/layout/ContainerScanningRefreshControls"
import { getToolEnabledOrgs } from "@/lib/server/tool-orgs"
import { getSession } from "@/lib/server/session"
import { checkToolPrerequisites } from "@/lib/server/settings-api"
import { can } from "@/lib/shared/auth/roles"
import { redirect } from "next/navigation"

export const metadata = { title: "Container Scanning" }

interface Props {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>
}

export default async function ContainerScanningDashboardPage({ searchParams }: Props) {
  const session = await getSession()
  if (!session) redirect("/login")
  const canEdit = can(session.role, "manage_settings")

  const orgs = await getToolEnabledOrgs("containerScanning")
  const hasOrgs = orgs.length > 0
  const orgLabel = hasOrgs ? orgs.join(", ") : "No organisations configured"
  const orgQuery = orgs.join(",")

  const sp = await searchParams
  const tabParam = typeof sp.tab === "string" ? sp.tab : undefined
  const { ready: scannerReady } = hasOrgs
    ? await checkToolPrerequisites("container-scanning", { id: session.userId, role: session.role, roleId: session.roleId })
    : { ready: false }
  const prerequisitesMet = hasOrgs && scannerReady
  const initialTab = tabParam ?? (!prerequisitesMet ? "settings" : "overview")

  return (
    <>
      <PageHeader
        icon={<ContainerIcon />}
        title="Container Scanning"
        description="Scans container images for vulnerabilities and misconfigurations"
        controls={<ContainerScanningRefreshControls org={orgQuery} orgLabel={orgLabel} />}
      />

      <main className="flex-1 max-w-7xl mx-auto w-full px-6 py-8">
        <ContainerScanningDashboardView org={orgQuery} initialTab={initialTab} canEdit={canEdit} prerequisitesMet={prerequisitesMet} />
      </main>
    </>
  )
}

function ContainerIcon() {
  return (
    <div className="p-1.5 bg-blue-50 dark:bg-blue-950 rounded-lg">
      <svg
        className="w-5 h-5 text-blue-500"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M21 7.5l-9-5.25L3 7.5m18 0l-9 5.25m9-5.25v9l-9 5.25M3 7.5l9 5.25M3 7.5v9l9 5.25m0-9v9" />
      </svg>
    </div>
  )
}
