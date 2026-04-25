import { NextRequest, NextResponse } from "next/server"
import { requireActiveUser } from "@/lib/server/auth/server"
import { forwardToBackend } from "@/lib/server/internal-api"

async function forwardSecretsRequest(request: NextRequest, ctx: { params: Promise<{ path?: string[] }> }) {
  const userOrResponse = await requireActiveUser()
  if (userOrResponse instanceof Response) return userOrResponse
  const params = await ctx.params
  const path = (params.path ?? []).join("/")
  return forwardToBackend(request, `/secrets/api/${path}`, userOrResponse)
}

export async function GET(request: NextRequest, ctx: { params: Promise<{ path?: string[] }> }) {
  return forwardSecretsRequest(request, ctx)
}

export async function POST(request: NextRequest, ctx: { params: Promise<{ path?: string[] }> }) {
  return forwardSecretsRequest(request, ctx)
}

export async function PATCH(request: NextRequest, ctx: { params: Promise<{ path?: string[] }> }) {
  return forwardSecretsRequest(request, ctx)
}
