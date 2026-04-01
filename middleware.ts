// middleware.ts
import { NextRequest, NextResponse } from "next/server"
import { decryptSession } from "@/lib/server/session-token"

const PUBLIC_PATHS = [
  "/login",
  "/login/verify",
  "/api/login",
  "/api/login/verify",
  "/api/logout",
  "/pending",
  "/docs",
  "/redoc",
  "/openapi.json",
]

function isPublicPath(pathname: string): boolean {
  return PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(p + "/"))
}

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  if (isPublicPath(pathname)) {
    return NextResponse.next()
  }

  const token = request.cookies.get("__session")?.value ?? null
  const session = token ? decryptSession(token) : null

  // Unauthenticated API requests get 401
  if (!session && pathname.startsWith("/api")) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  // Unauthenticated page requests redirect to login
  if (!session) {
    return NextResponse.redirect(new URL("/login", request.url))
  }

  // Pending users can only access /pending
  if (session.status === "pending" && !pathname.startsWith("/pending")) {
    return NextResponse.redirect(new URL("/pending", request.url))
  }

  // Active users on /pending redirect to home
  if (session.status === "active" && pathname.startsWith("/pending")) {
    return NextResponse.redirect(new URL("/", request.url))
  }

  return NextResponse.next()
}

export const runtime = "nodejs"

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:png|jpg|jpeg|gif|svg|ico|webp|woff|woff2|ttf|eot)$).*)",
  ],
}
