import { NextRequest } from "next/server"
import { requireActiveUser } from "@/lib/server/auth/server"
import { signInternalJwt } from "@/lib/server/jwt-internal"

const FASTAPI_URL = process.env.FASTAPI_URL ?? "http://localhost:8000"

export const dynamic = "force-dynamic"

export async function GET(request: NextRequest) {
  const userOrResponse = await requireActiveUser()
  if (userOrResponse instanceof Response) return userOrResponse

  const jwt = signInternalJwt(userOrResponse.id, userOrResponse.role, userOrResponse.roleId)
  const backendUrl = `${FASTAPI_URL}/events/api/stream`

  const backendResponse = await fetch(backendUrl, {
    headers: {
      Authorization: `Bearer ${jwt}`,
      Accept: "text/event-stream",
    },
    cache: "no-store",
    // @ts-expect-error — duplex needed for streaming in Node.js
    duplex: "half",
  })

  if (!backendResponse.ok || !backendResponse.body) {
    return new Response(
      JSON.stringify({ error: "SSE connection failed" }),
      { status: backendResponse.status, headers: { "Content-Type": "application/json" } },
    )
  }

  return new Response(backendResponse.body, {
    status: 200,
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  })
}
