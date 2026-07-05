import { NextRequest } from "next/server"
import { requirePermission } from "@/lib/server/auth/server"
import { forwardToBackend } from "@/lib/server/internal-api"

async function handle(
  request: NextRequest,
  { params }: { params: Promise<{ framework: string }> },
) {
  const userOrResponse = await requirePermission("view_findings")
  if (userOrResponse instanceof Response) return userOrResponse
  const { framework } = await params
  const search = request.nextUrl.search
  return forwardToBackend(
    request,
    `/api/v1/compliance/frameworks/${encodeURIComponent(framework)}/summary${search}`,
    userOrResponse,
  )
}

export const GET = handle
