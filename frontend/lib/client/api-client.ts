"use client"

import { ApiClientError, CsrfMissingError } from "./api-client.types.ts"

const CSRF_COOKIE_NAME = "__Host-csrf"
const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"])

export interface ApiClientOptions extends Omit<RequestInit, "body"> {
  method?: string
  body?: unknown
  headers?: Record<string, string>
  // Set true for auth endpoints (login, login/verify) that expect 401 to
  // mean "show the error" rather than "redirect to /login".
  suppressUnauthorizedRedirect?: boolean
  // Set true for pre-session POSTs (login, login/verify) — the backend
  // CSRF middleware bypasses requests without a session cookie, so the
  // client must skip its double-submit check too.
  skipCsrf?: boolean
}

function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null
  const pairs = document.cookie.split(";").map((p) => p.trim())
  for (const pair of pairs) {
    const [k, ...rest] = pair.split("=")
    if (k === name) return rest.join("=")
  }
  return null
}

export async function apiClient<T = unknown>(
  url: string,
  options: ApiClientOptions = {},
): Promise<T> {
  const {
    suppressUnauthorizedRedirect,
    skipCsrf,
    body: optionsBody,
    method: optionsMethod,
    headers: optionsHeaders,
    ...rest
  } = options
  const method = (optionsMethod ?? "GET").toUpperCase()
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...optionsHeaders,
  }

  let body: BodyInit | undefined
  if (optionsBody !== undefined) {
    if (typeof optionsBody === "string" || optionsBody instanceof FormData) {
      body = optionsBody as BodyInit
    } else {
      headers["Content-Type"] ??= "application/json"
      body = JSON.stringify(optionsBody)
    }
  }

  if (UNSAFE_METHODS.has(method) && !skipCsrf) {
    const csrf = readCookie(CSRF_COOKIE_NAME)
    if (csrf === null) throw new CsrfMissingError()
    headers["X-CSRF-Token"] = csrf
  }

  const response = await fetch(url, {
    ...rest,
    method,
    headers,
    body,
    credentials: "include",
  })

  if (response.status === 401) {
    if (typeof window !== "undefined" && !suppressUnauthorizedRedirect) {
      window.location.assign("/login")
    }
    throw new ApiClientError(401, await safeReadBody(response), "unauthorized")
  }

  if (response.status === 204) {
    return undefined as T
  }

  if (!response.ok) {
    throw new ApiClientError(response.status, await safeReadBody(response))
  }

  const contentType = response.headers.get("Content-Type") ?? ""
  if (contentType.includes("application/json")) {
    return (await response.json()) as T
  }
  return (await response.text()) as T
}

async function safeReadBody(response: Response): Promise<unknown> {
  try {
    const ct = response.headers.get("Content-Type") ?? ""
    if (ct.includes("application/json")) return await response.json()
    return await response.text()
  } catch {
    return null
  }
}
