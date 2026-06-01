import type { Finding as ApiFinding } from "../../client/findings-api.ts"
import { timeAgo } from "../time-ago.ts"

export type FindingSeverity = "critical" | "high" | "medium" | "low"
export type FindingScanner = "deps" | "sast" | "containers" | "secrets" | "iac"

export interface FindingRow {
  id: string
  title: string
  cve?: string
  severity: FindingSeverity
  scanner: FindingScanner
  repo: string
  filePath?: string
  age: string
  riskScore?: number
  /** EPSS percentile in [0.0, 1.0] from the FIRST.org feed (Phase 50). */
  epssPercentile?: number
}

// The aggregated endpoint emits the short scanner form `container`; the UI
// uses `containers` (plural) for the cell label/colour lookup. Unknown
// scanners fall back to the `deps` styling rather than crashing the row.
const SCANNER_MAP: Record<string, FindingScanner> = {
  deps: "deps",
  container: "containers",
  containers: "containers",
  sast: "sast",
  secrets: "secrets",
  iac: "iac",
}

export function normaliseScanner(raw: string): FindingScanner {
  return SCANNER_MAP[raw] ?? "deps"
}

export function normaliseSeverity(raw: string | null): FindingSeverity {
  if (raw === "critical" || raw === "high" || raw === "medium" || raw === "low") {
    return raw
  }
  return "low"
}

function buildRepoLabel(api: ApiFinding): string {
  if (api.repo) return api.repo
  if (api.package) return api.package
  return api.org_id
}

function buildFilePath(api: ApiFinding): string | undefined {
  if (!api.file_path) return undefined
  return api.line != null ? `${api.file_path}:${api.line}` : api.file_path
}

function buildAge(api: ApiFinding): string {
  const ts = api.created_at ?? api.updated_at
  if (!ts) return "—"
  return timeAgo(ts)
}

export function mapApiFinding(api: ApiFinding): FindingRow {
  return {
    id: api.id,
    title: api.title ?? api.cve ?? "Untitled finding",
    cve: api.cve ?? undefined,
    severity: normaliseSeverity(api.severity),
    scanner: normaliseScanner(api.scanner),
    repo: buildRepoLabel(api),
    filePath: buildFilePath(api),
    age: buildAge(api),
    epssPercentile: api.epssPercentile ?? undefined,
  }
}
