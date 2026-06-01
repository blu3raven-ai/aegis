import { NextRequest } from "next/server"
import { requireActiveUser } from "@/lib/server/auth/server"
import { forwardToBackend } from "@/lib/server/internal-api"

async function handle(request: NextRequest, ctx: { params: Promise<{ path?: string[] }> }) {
  const userOrResponse = await requireActiveUser()
  if (userOrResponse instanceof Response) return userOrResponse
  const params = await ctx.params
  const path = (params.path ?? []).join("/")
  return forwardToBackend(request, `/api/v1/sboms/${path}`, userOrResponse)
}

export const GET = handle
