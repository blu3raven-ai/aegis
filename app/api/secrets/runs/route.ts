import { NextRequest } from "next/server"
import { requireActiveUser, requirePermission } from "@/lib/server/auth/server"
import { forwardToBackend } from "@/lib/server/internal-api"

export async function GET(request: NextRequest) {
  const userOrResponse = await requireActiveUser()
  if (userOrResponse instanceof Response) return userOrResponse
  return forwardToBackend(request, "/secrets/api/runs", userOrResponse)
}

export async function POST(request: NextRequest) {
  const userOrResponse = await requirePermission("run_scans")
  if (userOrResponse instanceof Response) return userOrResponse
  return forwardToBackend(request, "/secrets/api/runs", userOrResponse)
}
