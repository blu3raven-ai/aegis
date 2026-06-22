import type { Finding as ApiFinding } from "../../client/findings-api.ts"
import { timeAgo } from "../time-ago.ts"

export type FindingSeverity = "critical" | "high" | "medium" | "low"
export type FindingScanner =
  | "dependencies_scanning"
  | "code_scanning"
  | "container_scanning"
  | "secret_scanning"
  | "iac_scanning"

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

// Canonical scanner names use the `<thing>_scanning` suffix. Unknown
// values fall back to dependencies-scanning styling rather than crashing
// the row.
const SCANNER_MAP: Record<string, FindingScanner> = {
  dependencies_scanning: "dependencies_scanning",
  code_scanning: "code_scanning",
  container_scanning: "container_scanning",
  secret_scanning: "secret_scanning",
  iac_scanning: "iac_scanning",
}

export function normaliseScanner(raw: string): FindingScanner {
  return SCANNER_MAP[raw] ?? "dependencies_scanning"
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

/**
 * Strip the runner's ephemeral clone prefix (".../workspace/job-<hash>/") and
 * any leading slashes so a path reads repo-relative instead of leaking the
 * scanner's working directory.
 */
function cleanWorkspacePath(path: string): string {
  return path.replace(/^.*?\/workspace\/job-[0-9a-f]+\//i, "").replace(/^\/+/, "")
}

function buildFilePath(api: ApiFinding): string | undefined {
  if (!api.file_path) return undefined
  const path = cleanWorkspacePath(api.file_path)
  return api.line != null ? `${path}:${api.line}` : path
}

/** Readable "basename:line" label from the structured file fields. */
function fileLabel(api: ApiFinding): string | undefined {
  if (!api.file_path) return undefined
  const file = cleanWorkspacePath(api.file_path).split("/").pop() || api.file_path
  return api.line != null ? `${file}:${api.line}` : file
}

/**
 * Some scanners use an opaque identity as the title: code-scanning leaks the
 * clone path + full rule id ("repo:/workspace/job-…/server.py:rule.path:93"),
 * and secret-scanning uses a hash of the secret value. Neither is readable, so
 * fall back to a file-location label from the structured fields.
 */
function buildTitle(api: ApiFinding): string {
  const raw = api.title ?? api.cve ?? ""
  const loc = fileLabel(api)
  if (loc && raw.includes("/workspace/job-")) {
    return loc
  }
  if (loc && normaliseScanner(api.scanner) === "secret_scanning" && /^[0-9a-f]{16,}$/i.test(raw)) {
    return `Secret in ${loc}`
  }
  return raw || "Untitled finding"
}

function buildAge(api: ApiFinding): string {
  const ts = api.created_at ?? api.updated_at
  if (!ts) return "—"
  return timeAgo(ts)
}

export function mapApiFinding(api: ApiFinding): FindingRow {
  return {
    id: api.id,
    title: buildTitle(api),
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
