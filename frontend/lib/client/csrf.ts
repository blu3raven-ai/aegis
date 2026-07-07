/**
 * CSRF cookie access shared by the REST and GraphQL browser clients.
 *
 * The backend sets a `__Host-`prefixed cookie whose value must be echoed in the
 * `X-CSRF-Token` header on unsafe (state-changing) requests.
 */

export const CSRF_COOKIE_NAME = "__Host-csrf"

/** Read the CSRF token from `document.cookie`, or `null` when unavailable (SSR / not set). */
export function readCsrfCookie(): string | null {
  if (typeof document === "undefined") return null
  for (const pair of document.cookie.split(";").map((p) => p.trim())) {
    const [k, ...rest] = pair.split("=")
    if (k === CSRF_COOKIE_NAME) return rest.join("=")
  }
  return null
}
