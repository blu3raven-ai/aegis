import type { Finding as ApiFinding } from "../../client/findings-api.ts"
import { timeAgo } from "../time-ago.ts"

export type FindingSeverity = "critical" | "high" | "medium" | "low"
export type FindingScanner = "deps" | "sast" | "containers" | "secrets" | "iac"

export interface FindingRecommendedFix {
  /** Optional one-line title, e.g. "Upgrade log4j-core". */
  title?: string
  packageName?: string
  fromVersion?: string
  toVersion?: string
  /** Free-form description, e.g. "Patch release · no API changes". */
  description?: string
  /** Snippet payload copied to clipboard by the drawer's Copy button. */
  snippet?: string
  /** Optional URL to a diff view. */
  diffUrl?: string
}

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
  /** Lifecycle state from the aggregated endpoint — null when the server omits it. */
  state?: string
  /** Whether the finding's CVE is in CISA KEV (server-supplied). */
  kev?: boolean
  /** First CWE id (e.g. "CWE-502") from KEV metadata. */
  cwe?: string
  /** ISO timestamp of when the finding was first detected. */
  firstSeen?: string
  /** Short SHA of the commit that introduced the finding. */
  introducedByCommit?: string
  /** Author handle (e.g. "@maya.l") credited with introducing the finding. */
  introducedByAuthor?: string
  /** PR URL that introduced the finding, when known. */
  introducedByPrUrl?: string
  /** Server-supplied recommended fix payload; absent when no fix is known. */
  recommendedFix?: FindingRecommendedFix
  /** Assigned reviewer's user id, or undefined when unassigned. */
  assigneeUserId?: string
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
    state: api.state ?? undefined,
    firstSeen: api.created_at ?? undefined,
    kev: api.kev ?? undefined,
    cwe: api.cwe ?? undefined,
    riskScore: api.risk_score ?? undefined,
    assigneeUserId: api.assignee_user_id ?? undefined,
  }
}
