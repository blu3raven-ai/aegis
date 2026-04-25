import { NextRequest } from "next/server"
import { requirePermission } from "@/lib/server/auth/server"
import { forwardToBackend } from "@/lib/server/internal-api"

export async function POST(request: NextRequest) {
  const userOrResponse = await requirePermission("run_scans")
  if (userOrResponse instanceof Response) return userOrResponse
  return forwardToBackend(request, "/secrets/api/runs/cancel", userOrResponse)
}
