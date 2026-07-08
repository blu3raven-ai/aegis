/**
 * True when `origin` points at the operator's own machine — an address no
 * external service (a provider webhook, a CI pipeline, or a remote runner) can
 * reach. Used to warn before a localhost URL is copied somewhere it will
 * silently never connect.
 */
export function isLocalOrigin(origin: string): boolean {
  try {
    const { hostname } = new URL(origin)
    return (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "0.0.0.0" ||
      hostname === "[::1]" ||
      hostname === "::1" ||
      hostname.endsWith(".localhost")
    )
  } catch {
    return false
  }
}
