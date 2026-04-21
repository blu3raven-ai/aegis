import { NextRequest } from "next/server"
import { forwardToBackend } from "@/lib/server/internal-api"

export async function GET(request: NextRequest) {
  return forwardToBackend(request, "/redoc", true)
}
