import { NextRequest, NextResponse } from "next/server"
import { deleteSession } from "@/lib/server/session"

export async function POST(request: NextRequest) {
  await deleteSession()
  return NextResponse.redirect(new URL("/login", request.url))
}
