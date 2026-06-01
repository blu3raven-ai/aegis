import { NextRequest } from "next/server"
import { requirePermission } from "@/lib/server/auth/server"
import { forwardToBackend } from "@/lib/server/internal-api"

async function handle(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const userOrResponse = await requirePermission("view_findings")
  if (userOrResponse instanceof Response) return userOrResponse
  const { path } = await params
  return forwardToBackend(request, `/api/v1/repos/${path.join("/")}`, userOrResponse)
}

export const GET = handle
