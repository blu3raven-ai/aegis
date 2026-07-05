import { redirect } from "next/navigation"
import { requirePermission } from "@/lib/server/auth/server"
import { can } from "@/lib/shared/auth/roles"
import { SourcesIndexClient } from "./SourcesIndexClient"

export const metadata = { title: "Sources" }

export default async function SourcesIndexPage({
  searchParams,
}: {
  searchParams: Promise<{ tab?: string }>
}) {
  const userOrResponse = await requirePermission("view_settings")
  if (userOrResponse instanceof Response) redirect("/")
  const canEdit = can(userOrResponse.role, "manage_settings")
  const params = await searchParams
  const initialTab =
    params.tab === "container-registry"
      ? "container-registry"
      : params.tab === "repositories"
        ? "repositories"
        : "code-repositories"
  return <SourcesIndexClient canEdit={canEdit} initialTab={initialTab} />
}
