import { NextRequest } from "next/server"
import { requireActiveUser } from "@/lib/server/auth/server"
import { forwardToBackend } from "@/lib/server/internal-api"

export async function GET(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const userOrResponse = await requireActiveUser()
  if (userOrResponse instanceof Response) return userOrResponse
  const { path } = await params
  return forwardToBackend(request, `/notifications/api/${path.join("/")}`, userOrResponse)
}

export async function POST(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const userOrResponse = await requireActiveUser()
  if (userOrResponse instanceof Response) return userOrResponse
  const { path } = await params
  return forwardToBackend(request, `/notifications/api/${path.join("/")}`, userOrResponse)
}

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const userOrResponse = await requireActiveUser()
  if (userOrResponse instanceof Response) return userOrResponse
  const { path } = await params
  return forwardToBackend(request, `/notifications/api/${path.join("/")}`, userOrResponse)
}
