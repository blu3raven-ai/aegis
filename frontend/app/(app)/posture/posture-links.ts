/** Build a deep link from a posture tile into the scoped Findings view.
 *  The Findings page reads these as display filters; the backend still enforces
 *  permission + asset scope, so a link can only narrow what the caller sees. */
export function findingsHref(params: { severity?: string; repo?: string }): string {
  const sp = new URLSearchParams()
  if (params.severity) sp.set("severity", params.severity)
  if (params.repo) sp.set("repo", params.repo)
  const qs = sp.toString()
  return qs ? `/findings?${qs}` : "/findings"
}
