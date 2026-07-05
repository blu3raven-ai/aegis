import { NextRequest } from "next/server"
import { requirePermission } from "@/lib/server/auth/server"
import { forwardToBackend } from "@/lib/server/internal-api"

async function handle(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> },
) {
  const userOrResponse = await requirePermission("manage_settings")
  if (userOrResponse instanceof Response) return userOrResponse
  const { path } = await params
  return forwardToBackend(request, `/api/v1/api-keys/${path.join("/")}`, userOrResponse)
}

export const GET = handle
export const POST = handle
export const DELETE = handle
