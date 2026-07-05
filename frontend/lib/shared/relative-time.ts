/**
 * Converts an ISO 8601 timestamp to a human-readable relative string,
 * e.g. "3 days ago". Used in attribution rows throughout the UI.
 *
 * Accepts null/undefined and returns "—" so call sites with nullable
 * timestamps (GraphQL Optional fields, REST payloads with missing dates)
 * don't have to guard at every usage.
 */
export function relativeTime(isoString: string | null | undefined): string {
  if (!isoString) return "—"
  const then = new Date(isoString).getTime()
  if (Number.isNaN(then)) return isoString

  const diffMs = Date.now() - then
  const diffSecs = Math.floor(diffMs / 1000)

  if (diffSecs < 60) return "just now"
  const diffMins = Math.floor(diffSecs / 60)
  if (diffMins < 60) return `${diffMins} minute${diffMins !== 1 ? "s" : ""} ago`
  const diffHours = Math.floor(diffMins / 60)
  if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? "s" : ""} ago`
  const diffDays = Math.floor(diffHours / 24)
  if (diffDays < 30) return `${diffDays} day${diffDays !== 1 ? "s" : ""} ago`
  const diffMonths = Math.floor(diffDays / 30)
  if (diffMonths < 12) return `${diffMonths} month${diffMonths !== 1 ? "s" : ""} ago`
  // Derive years from the same 30-day month basis as the months branch; dividing
  // diffDays by 365 here left a 360–364 day gap that rendered "0 years ago".
  const diffYears = Math.floor(diffMonths / 12)
  return `${diffYears} year${diffYears !== 1 ? "s" : ""} ago`
}
