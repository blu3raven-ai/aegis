import "server-only"

import { getSessionCookieHeader } from "@/lib/server/session"

const FASTAPI_URL = process.env.FASTAPI_URL ?? "http://localhost:8000"

/**
 * Authenticated GET to the FastAPI backend, forwarding the user's session cookie.
 * The `user` parameter is retained for call-site compatibility but is not used —
 * the session cookie is the authoritative credential after the BFF was removed.
 */
export async function getJson<T>(
  backendPath: string,
  _user?: { id: string; role: string; roleId?: string | null },
): Promise<T> {
  const cookieHeader = await getSessionCookieHeader()
  const url = `${FASTAPI_URL}${backendPath}${backendPath.includes("?") ? "&" : "?"}t=${Date.now()}`

  const headers: Record<string, string> = {
    Accept: "application/json",
  }
  if (cookieHeader) headers["Cookie"] = cookieHeader

  const response = await fetch(url, {
    headers,
    cache: "no-store",
  })

  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.detail || body.error || `Backend request failed (${response.status})`)
  }

  return (await response.json()) as T
}

/**
 * Authenticated POST/PATCH to the FastAPI backend, forwarding the user's session cookie.
 * The `user` parameter is retained for call-site compatibility but is not used.
 */
export async function postJson<T>(
  backendPath: string,
  _user: { id: string; role: string; roleId?: string | null },
  body: unknown,
  method: "POST" | "PATCH" = "POST",
): Promise<T> {
  const cookieHeader = await getSessionCookieHeader()
  const url = `${FASTAPI_URL}${backendPath}`

  const headers: Record<string, string> = {
    Accept: "application/json",
    "Content-Type": "application/json",
  }
  if (cookieHeader) headers["Cookie"] = cookieHeader

  const response = await fetch(url, {
    method,
    headers,
    body: JSON.stringify(body),
    cache: "no-store",
  })

  if (!response.ok) {
    const responseBody = await response.json().catch(() => ({}))
    throw new Error(responseBody.detail || responseBody.error || `Backend request failed (${response.status})`)
  }

  return (await response.json()) as T
}
