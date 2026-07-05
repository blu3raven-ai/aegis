import type { SbomDiffResponse, VulnCounts } from "@/lib/client/sbom-diff-api"

/** One flat row per changed component, so an SBOM comparison can be attached to
 *  an upgrade-review ticket or opened in a spreadsheet. The data is already
 *  loaded client-side, so the export is generated in the browser — no backend. */

const COLUMNS = [
  "change",
  "name",
  "ecosystem",
  "from_version",
  "to_version",
  "purl",
  "advisories_known",
  "advisories_resolved",
  "advisories_introduced",
  "advisories_still_vulnerable",
  "open_findings",
  "license_from",
  "license_to",
] as const

/** RFC-4180 field quoting — wrap in quotes and double any embedded quote when
 *  the value contains a comma, quote, or newline. */
function esc(value: string | number | null | undefined): string {
  const s = value == null ? "" : String(value)
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

/** Empty string when the count is absent or zero, so a spreadsheet reads blanks
 *  rather than a sea of noisy zeroes; the tier detail lives in the UI. */
function total(counts: VulnCounts | undefined): string {
  return counts && counts.total > 0 ? String(counts.total) : ""
}

/** Serialize a loaded diff to CSV text. On a server-capped (`truncated`) diff
 *  this reflects the loaded rows only — the same subset the table renders. */
export function diffToCsv(diff: SbomDiffResponse): string {
  const rows: string[][] = [[...COLUMNS]]

  for (const c of diff.added) {
    rows.push([
      "added", c.name, c.type ?? "", "", c.version ?? "", c.purl ?? "",
      total(c.known_vulns), "", "", "", total(c.current_findings), "", "",
    ])
  }
  for (const c of diff.removed) {
    rows.push([
      "removed", c.name, c.type ?? "", c.version ?? "", "", c.purl ?? "",
      total(c.known_vulns), "", "", "", total(c.current_findings), "", "",
    ])
  }
  for (const v of diff.version_changed) {
    rows.push([
      "version_changed", v.name, v.type ?? "", v.from_version ?? "", v.to_version ?? "", v.purl ?? "",
      "", total(v.resolved), total(v.introduced), total(v.still_vulnerable), total(v.current_findings),
      v.from_license ?? "", v.to_license ?? "",
    ])
  }

  return rows.map((r) => r.map(esc).join(",")).join("\r\n")
}
