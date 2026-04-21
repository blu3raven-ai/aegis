import { NextRequest } from "next/server"
import { requireUser, requirePermission } from "@/lib/server/auth/server"
import { forwardToBackend } from "@/lib/server/internal-api"

export async function GET(request: NextRequest, ctx: { params: Promise<{ path?: string[] }> }) {
  const userOrResponse = await requirePermission("manage_settings")
  if (userOrResponse instanceof Response) return userOrResponse
  const params = await ctx.params
  const path = (params.path ?? []).join("/")
  return forwardToBackend(request, `/settings/api/${path}`, userOrResponse)
}

async function forwardSettingsMutation(request: NextRequest, ctx: { params: Promise<{ path?: string[] }> }) {
  const userOrResponse = await requirePermission("manage_settings")
  if (userOrResponse instanceof Response) return userOrResponse
  const params = await ctx.params
  const path = (params.path ?? []).join("/")
  return forwardToBackend(request, `/settings/api/${path}`, userOrResponse)
}

export const PUT = forwardSettingsMutation
export const PATCH = forwardSettingsMutation
export const POST = forwardSettingsMutation
export const DELETE = forwardSettingsMutation
