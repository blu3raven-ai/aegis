import { NextRequest } from "next/server"
import { requirePermission } from "@/lib/server/auth/server"
import { forwardToBackend } from "@/lib/server/internal-api"

async function handle(request: NextRequest) {
  const userOrResponse = await requirePermission("manage_settings")
  if (userOrResponse instanceof Response) return userOrResponse
  return forwardToBackend(request, "/api/v1/api-keys", userOrResponse)
}

export const GET = handle
export const POST = handle
