import { redirect } from "next/navigation"
import { requirePermission } from "@/lib/server/auth/server"
import { can } from "@/lib/shared/auth/roles"
import { SourcePageShell } from "@/app/(app)/sources/_components/SourcePageShell"

export const metadata = { title: "Git Repository — Sources" }

function GitRepoIcon() {
  return (
    <div className="p-1.5 bg-blue-50 dark:bg-blue-950 rounded-lg">
      <svg className="w-5 h-5 text-blue-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
        <path d="M14.25 9.75 16.5 12l-2.25 2.25m-4.5 0L7.5 12l2.25-2.25M6 20.25h12A2.25 2.25 0 0 0 20.25 18V6A2.25 2.25 0 0 0 18 3.75H6A2.25 2.25 0 0 0 3.75 6v12A2.25 2.25 0 0 0 6 20.25Z" />
      </svg>
    </div>
  )
}

export default async function CodeRepositoriesPage() {
  const userOrResponse = await requirePermission("view_settings")
  if (userOrResponse instanceof Response) redirect("/")
  const canEdit = can(userOrResponse.role, "manage_settings")
  return <SourcePageShell category="code-repositories" canEdit={canEdit} icon={<GitRepoIcon />} />
}
