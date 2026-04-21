import { NextRequest } from "next/server"
import { requireActiveUser } from "@/lib/server/auth/server"
import { forwardToBackend } from "@/lib/server/internal-api"

export async function POST(request: NextRequest) {
  const userOrResponse = await requireActiveUser()
  if (userOrResponse instanceof Response) return userOrResponse
  return forwardToBackend(request, "/graphql/api", userOrResponse)
}
