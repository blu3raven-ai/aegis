import { NextRequest } from "next/server"
import { requirePermission } from "@/lib/server/auth/server"
import { forwardToBackend } from "@/lib/server/internal-api"

async function handle(
  request: NextRequest,
  { params }: { params: Promise<{ findingId: string }> },
) {
  const userOrResponse = await requirePermission("view_findings")
  if (userOrResponse instanceof Response) return userOrResponse
  const { findingId } = await params
  return forwardToBackend(
    request,
    `/api/v1/compliance/findings/${encodeURIComponent(findingId)}/controls`,
    userOrResponse,
  )
}

export const GET = handle
