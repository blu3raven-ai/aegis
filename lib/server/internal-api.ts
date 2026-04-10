import { NextRequest, NextResponse } from "next/server"
import { signInternalJwt } from "./jwt-internal"
import type { DashboardUser } from "./auth/users.ts"
import { createLogger } from "@/lib/server/logger"

const log = createLogger("api")

const FASTAPI_URL = process.env.FASTAPI_URL ?? "http://localhost:8000"

export async function forwardToBackend(
  request: NextRequest,
  backendPath: string,
  user: DashboardUser | boolean | null,
) {
  // Reject path traversal attempts — no legitimate API path contains ".."
  if (backendPath.includes("..")) {
    return NextResponse.json({ error: "Invalid path" }, { status: 400 })
  }

  const url = new URL(`${FASTAPI_URL}${backendPath}`)
  url.search = request.nextUrl.search

  const hasBody = request.method !== "GET" && request.method !== "HEAD"
  
  const headers: Record<string, string> = {
    Accept: request.headers.get("accept") ?? "application/json",
    "Content-Type": request.headers.get("content-type") ?? "application/json",
  }

  if (user && typeof user !== "boolean") {
    const jwt = signInternalJwt(user.id, user.role, user.roleId)
    headers["Authorization"] = `Bearer ${jwt}`
  }

  const abort = new AbortController()
  const timeout = setTimeout(() => abort.abort(), 60_000)

  try {
    const response = await fetch(url, {
      method: request.method,
      body: hasBody ? request.body : undefined,
      headers,
      cache: "no-store",
      signal: abort.signal,
      // duplex: "half" is required in Node.js when body is a stream
      ...(hasBody ? { duplex: "half" } : {}),
    } as RequestInit)

    return new NextResponse(response.body, {
      status: response.status,
      headers: {
        "Content-Type": response.headers.get("content-type") ?? "application/json",
      },
    })
  } catch (err: any) {
    if (err.name === "AbortError") {
      return NextResponse.json({ error: "Backend request timed out" }, { status: 504 })
    }
    log.error("forwardToBackend error:", err)
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 })
  } finally {
    clearTimeout(timeout)
  }
}

export async function getJson<T>(
  backendPath: string,
  user: { id: string; role: string; roleId?: string | null },
): Promise<T> {
  const jwt = signInternalJwt(user.id, user.role as any, user.roleId)
  const url = `${FASTAPI_URL}${backendPath}${backendPath.includes("?") ? "&" : "?"}t=${Date.now()}`

  const response = await fetch(url, {
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${jwt}`,
    },
    cache: "no-store",
  })

  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.detail || body.error || `Backend request failed (${response.status})`)
  }

  return (await response.json()) as T
}

export async function postJson<T>(
  backendPath: string,
  user: { id: string; role: string; roleId?: string | null },
  body: unknown,
  method: "POST" | "PATCH" = "POST",
): Promise<T> {
  const jwt = signInternalJwt(user.id, user.role as any, user.roleId)
  const url = `${FASTAPI_URL}${backendPath}`

  const response = await fetch(url, {
    method,
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      Authorization: `Bearer ${jwt}`,
    },
    body: JSON.stringify(body),
    cache: "no-store",
  })

  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.detail || body.error || `Backend request failed (${response.status})`)
  }

  return (await response.json()) as T
}
