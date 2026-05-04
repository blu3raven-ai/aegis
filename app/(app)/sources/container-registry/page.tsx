import { redirect } from "next/navigation"
import { requirePermission } from "@/lib/server/auth/server"
import { can } from "@/lib/shared/auth/roles"
import { SourcePageShell } from "@/app/(app)/sources/_components/SourcePageShell"

export const metadata = { title: "Container Registry — Sources" }

function ContainerRegistryIcon() {
  return (
    <div className="p-1.5 bg-blue-50 dark:bg-blue-950 rounded-lg">
      <svg className="w-5 h-5 text-blue-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
        <path d="M20.25 7.5l-.625 10.632a2.25 2.25 0 0 1-2.247 2.118H6.622a2.25 2.25 0 0 1-2.247-2.118L3.75 7.5M10 11.25h4M3.375 7.5h17.25c.621 0 1.125-.504 1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125H3.375c-.621 0-1.125.504-1.125 1.125v1.5c0 .621.504 1.125 1.125 1.125Z" />
      </svg>
    </div>
  )
}

export default async function ContainerRegistryPage() {
  const userOrResponse = await requirePermission("view_settings")
  if (userOrResponse instanceof Response) redirect("/")
  const canEdit = can(userOrResponse.role, "manage_settings")
  return <SourcePageShell category="container-registry" canEdit={canEdit} icon={<ContainerRegistryIcon />} />
}
