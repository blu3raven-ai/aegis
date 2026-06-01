import { CodeScanningDashboardView } from "@/app/(app)/code/_components/code-scanning-dashboard-view"
import { PageHeader } from "@/components/layout/PageHeader"
import { CodeScanningRefreshControls } from "@/components/layout/CodeScanningRefreshControls"
import { getToolEnabledOrgs } from "@/lib/server/tool-orgs"
import { getSession } from "@/lib/server/session"
import { checkToolPrerequisites } from "@/lib/server/settings-api"
import { can } from "@/lib/shared/auth/roles"
import { redirect } from "next/navigation"

export const metadata = { title: "Code Scanning (SAST)" }

export default async function CodeScanningDashboardPage({
  searchParams,
}: {
  searchParams: Promise<{ tab?: string }>
}) {
  const session = await getSession()
  if (!session) redirect("/login")

  const { tab } = await searchParams
  const orgs = await getToolEnabledOrgs("codeScanning")
  const hasOrgs = orgs.length > 0
  const orgLabel = hasOrgs ? orgs.join(", ") : "No organisations configured"
  const orgQuery = orgs.join(",")
  const canEdit = can(session.role, "manage_settings")
  const { ready: scannerReady } = hasOrgs
    ? await checkToolPrerequisites("code_scanning", { id: session.userId, role: session.role, roleId: session.roleId })
    : { ready: false }
  const prerequisitesMet = hasOrgs && scannerReady
  const initialTab = tab ?? (!prerequisitesMet ? "settings" : "overview")

  return (
    <>
      <PageHeader
        icon={<CodeScanningIcon />}
        title="Code Scanning"
        description="Analyzes source code for security vulnerabilities and coding issues"
        controls={<CodeScanningRefreshControls org={orgQuery} orgLabel={orgLabel} />}
      />
      <main className="flex-1 max-w-7xl mx-auto w-full px-6 py-8">
        <CodeScanningDashboardView org={orgQuery} initialTab={initialTab} canEdit={canEdit} prerequisitesMet={prerequisitesMet} />
      </main>
    </>
  )
}

function CodeScanningIcon() {
  return (
    <div className="p-1.5 bg-[var(--color-accent-subtle)] rounded-lg">
      <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5 text-[var(--color-accent)]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75 22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3-4.5 16.5" />
      </svg>
    </div>
  )
}
