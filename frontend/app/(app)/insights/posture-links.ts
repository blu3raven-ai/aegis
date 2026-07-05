/** Build a deep link from a posture tile into the scoped Findings view.
 *  The Findings page reads these as display filters; the backend still enforces
 *  permission + asset scope, so a link can only narrow what the caller sees.
 *  Only params the Findings page actually consumes are accepted — adding a
 *  param it ignores would produce a dead link. */
export function findingsHref(params: {
  severity?: string
  repo?: string
  scanner?: string
  kev?: boolean
  /** EPSS percentile floor, a 0-1 fraction (e.g. 0.9 = 90th percentile).
   *  Mirrors the backend epss_min query param (clamped to [0,1] server-side). */
  epssMin?: number
  /** Finding state bucket, e.g. "open". Set this when the source tile counts a
   *  single state (posture tiles count open findings) so the linked view shows
   *  the same set rather than defaulting to all states. */
  state?: string
  finding?: string
  /** Age preset filter — must be a value accepted by FindingsBoardView (e.g. "90d"). */
  age?: string
}): string {
  const sp = new URLSearchParams()
  if (params.severity) sp.set("severity", params.severity)
  if (params.repo) sp.set("repo", params.repo)
  if (params.scanner) sp.set("scanner", params.scanner)
  if (params.kev) sp.set("kev", "true")
  if (params.epssMin != null) sp.set("epss_min", String(params.epssMin))
  if (params.state) sp.set("state", params.state)
  if (params.finding) sp.set("finding", params.finding)
  if (params.age) sp.set("age", params.age)
  const qs = sp.toString()
  return qs ? `/findings?${qs}` : "/findings"
}
