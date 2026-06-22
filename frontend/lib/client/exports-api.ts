/**
 * Client helper for the findings bulk export endpoint.
 *
 * Returns a URL instead of a Promise so the browser can open it directly as a
 * file download — no need to buffer the full response body in JS.  Auth is
 * handled by the existing session cookie forwarded through the Next.js BFF
 * proxy.
 */

export interface FindingExportFilters {
  severity?: string        // comma-separated, e.g. "critical,high"
  scanner?: string         // comma-separated, e.g. "dependencies,secrets"
  status?: string          // comma-separated, e.g. "open,dismissed"
  repo_id?: string         // single repository slug "owner/name"
  since?: string           // ISO-8601 datetime or duration like "30d"
  until?: string           // ISO-8601 datetime
  include_archived?: boolean  // compliance opt-in: include archived findings
}

/**
 * Build a URL that the browser can open to trigger a streaming download of
 * findings.  Active filters from the findings page are forwarded so the
 * downloaded file matches exactly what the user is currently viewing.
 */
export function buildFindingsExportUrl(
  filters: FindingExportFilters,
  format: "csv" | "json",
): string {
  const qs = new URLSearchParams()
  qs.set("format", format)
  if (filters.severity) qs.set("severity", filters.severity)
  if (filters.scanner) qs.set("scanner", filters.scanner)
  if (filters.status) qs.set("status", filters.status)
  if (filters.repo_id) qs.set("repo_id", filters.repo_id)
  if (filters.since) qs.set("since", filters.since)
  if (filters.until) qs.set("until", filters.until)
  if (filters.include_archived) qs.set("include_archived", "true")
  return `/api/v1/findings/export?${qs.toString()}`
}
