/** Client for the findings surface (list, summary, mutations, assignees). */

import { apiClient } from "./api-client.ts"
import { readCsrfCookie } from "./csrf.ts"
import type {
  FindingRecommendedFix,
  VerificationMetadata,
} from "../shared/findings/row-mapper.ts"

export type FindingSeverity = "critical" | "high" | "medium" | "low"
export type FindingScanner =
  | "dependencies_scanning"
  | "code_scanning"
  | "container_scanning"
  | "secret_scanning"
  | "iac_scanning"
  | "agent_scanning"

// The findings API returns the public shorthand (deps/sast/secrets/container);
// the rest of the UI keys off the internal scanner names, so normalise on read.
const SCANNER_SHORTHAND_TO_NAME: Record<string, FindingScanner> = {
  deps: "dependencies_scanning",
  sast: "code_scanning",
  secrets: "secret_scanning",
  container: "container_scanning",
  iac: "iac_scanning",
  agent: "agent_scanning",
}

function normalizeScanner(scanner: string): string {
  return SCANNER_SHORTHAND_TO_NAME[scanner] ?? scanner
}
export type FindingState = "open" | "closed" | "dismissed" | "fixed" | "deferred"
export type FindingVerdict = "confirmed" | "needs_verify" | "possible" | "ruled_out"
export type FindingVerdictFilter = FindingVerdict | "legacy" | "all"
export type FindingSort =
  | "severity"
  | "created_at"
  | "updated_at"
  | "severity_age"
  | "epss"
  | "cvss"
  | "risk_score"
  | "action_band"
  | "newest"
  | "oldest"
export type FindingSortDirection = "asc" | "desc"

export interface Finding {
  id: string
  scanner: FindingScanner | string
  severity: FindingSeverity | string | null
  state: string | null
  title: string | null
  cve: string | null
  package: string | null
  file_path: string | null
  line: number | null
  repo: string | null
  repo_html_url?: string | null
  org_id: string
  created_at: string | null
  updated_at: string | null
  /** EPSS percentile in [0.0, 1.0]. */
  epssPercentile?: number | null
  /** True when this finding's CVE is in CISA KEV. */
  kev?: boolean | null
  /** True when this is a malicious-package report (remove, don't upgrade). */
  malicious?: boolean | null
  /** First CWE id (e.g. "CWE-502") from KEV metadata. */
  cwe?: string | null
  risk_score?: number | null
  /** CVSS 3.1 base score (0.0–10.0), promoted from verification metadata. */
  cvss_score?: number | null
  /** SSVC-style triage band derived from KEV + reachability + severity. */
  action_band?: string | null
  assignee_user_id?: string | null
  verdict?: FindingVerdict | null
  /** One-line disproof shown on ruled-out rows; null for other verdicts. */
  ruled_out_reason?: string | null
  /** Short, client-safe code/context preview (redacted for secrets). */
  code_snippet?: string | null
  /** 1-indexed file line of the snippet's first line, for gutter anchoring. */
  code_snippet_start_line?: number | null
  /** Offending line range to highlight within the snippet. */
  code_highlight_start?: number | null
  code_highlight_end?: number | null
  /** Scanner's explanation of the issue (what's wrong). */
  description?: string | null
  /** Rule that fired (name or id). */
  rule?: string | null
  /** Remediation guidance (how to fix). */
  remediation?: string | null
  /** Scanner confidence (e.g. "high"). */
  confidence?: string | null
  /** Secret detector that fired (e.g. "AWS secret"). Secret findings only. */
  secret_detector?: string | null
  /** Whether the secret was confirmed live; null when the detector can't validate. */
  secret_verified?: boolean | null
  /** Commit that introduced the finding, when the scanner captured it. */
  introduced_by_commit?: string | null
  /** Blast radius: other in-scope repos with an active finding for this CVE/package. */
  also_affects_repos?: number | null
  /** Image context for container findings (name/tag/digest/base OS/layers). */
  container_image?: {
    name: string
    tag: string | null
    digest: string | null
    base_os: string | null
    layer_count: number | null
    layer_digest: string | null
    layer_index: number | null
    newer_tags: string[] | null
    /** Most-affected layer across this image's open findings (detail-fetch only). */
    layer_concentration: {
      layer_index: number
      finding_count: number
      total_with_layer: number
    } | null
    /** Newer base tag with fewer vulns, proven by rescanning (detail-fetch only). */
    base_image_recommendation: {
      recommended_tag: string
      current_vuln_count: number
      recommended_vuln_count: number
    } | null
  } | null
  /** Ordered taint path (source → sink) for SAST flow findings. */
  code_flows?: Array<{ file: string; line: number; snippet?: string }> | null
  /** Structured remediation payload (see FindingRecommendedFix). The API passes
   *  the object through untouched, so every fix `kind` reaches the drawer. */
  recommended_fix?: FindingRecommendedFix | null
  /** Argus-verification evidence citations (source/sink/gate) — detail fetch only. */
  evidence?: Array<{ file?: string; line?: number; snippet?: string; kind?: string }> | null
  /** Verifier's exploit-chain narrative — detail fetch only. */
  exploit_chain?: string | null
  /** Verifier model/token footer + ruled-out mitigation — detail fetch only. */
  verification_metadata?: VerificationMetadata | null
  /** Runner-derived reachability ("reachable" | "no_path" | "unknown") — detail fetch only. */
  reachability?: string | null
}

export interface ListFindingsParams {
  orgId: string
  severity?: FindingSeverity[]
  scanner?: FindingScanner[]
  state?: FindingState[]
  q?: string
  cve?: string
  repo?: string
  sort?: FindingSort
  direction?: FindingSortDirection
  limit?: number
  page?: number
  first_seen_after?: string
  cwe?: string
  kev?: boolean
  epss_min?: number
  bands?: ("act" | "attend" | "track")[]
  assignee?: string
  verdict?: FindingVerdictFilter
}

export interface VerdictCounts {
  total: number
  confirmed: number
  needs_verify: number
  possible: number
  ruled_out: number
  legacy: number
}

export interface FindingsListResponse {
  findings: Finding[]
  next_cursor: string | null
  total_count: number
  verdict_counts?: VerdictCounts
}

interface GqlFindingRow {
  id: string
  scanner: string
  severity: string | null
  state: string | null
  title: string | null
  cve: string | null
  package: string | null
  filePath: string | null
  line: number | null
  repo: string | null
  orgId: string
  createdAt: string | null
  updatedAt: string | null
  epssPercentile: number | null
  kev: boolean | null
  cwe: string | null
  riskScore: number | null
  cvssScore: number | null
  actionBand: string | null
  assigneeUserId: string | null
  verdict: FindingVerdict | null
  ruledOutReason: string | null
}

interface GqlVerdictCounts {
  total: number
  confirmed: number
  needsVerify: number
  possible: number
  ruledOut: number
  legacy: number
}

interface GqlFindingsSearchResponse {
  findings: {
    search: {
      findings: GqlFindingRow[]
      nextCursor: string | null
      totalCount: number
      verdictCounts: GqlVerdictCounts | null
    }
  }
}
async function postGql<T>(
  operationName: string,
  query: string,
  variables?: Record<string, unknown>,
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  }
  const csrf = readCsrfCookie()
  if (csrf !== null) headers["X-CSRF-Token"] = csrf

  const res = await fetch("/api/v1/graphql", {
    method: "POST",
    headers,
    body: JSON.stringify({ operationName, query, variables }),
    credentials: "include",
  })
  if (!res.ok) throw new Error(`${operationName} failed: ${res.status}`)
  const body = (await res.json()) as { data?: T; errors?: { message: string }[] }
  if (body.errors && body.errors.length > 0) {
    throw new Error(body.errors[0].message)
  }
  if (!body.data) {
    throw new Error(`${operationName} returned no data`)
  }
  return body.data
}

function fromGqlRow(row: GqlFindingRow): Finding {
  return {
    id: row.id,
    scanner: normalizeScanner(row.scanner),
    severity: row.severity,
    state: row.state,
    title: row.title,
    cve: row.cve,
    package: row.package,
    file_path: row.filePath,
    line: row.line,
    repo: row.repo,
    org_id: row.orgId,
    created_at: row.createdAt,
    updated_at: row.updatedAt,
    epssPercentile: row.epssPercentile,
    kev: row.kev,
    cwe: row.cwe,
    risk_score: row.riskScore,
    cvss_score: row.cvssScore,
    action_band: row.actionBand,
    assignee_user_id: row.assigneeUserId,
    verdict: row.verdict,
    ruled_out_reason: row.ruledOutReason ?? null,
  }
}

export interface FindingsSummary {
  open: number
  critical: number
  high: number
  medium: number
  low: number
  fixed_recent: number
  dismissed: number
  fixed_window_days: number
}

/** Cross-scanner KPI counts for the findings page. */
export async function listFindingsSummary(): Promise<FindingsSummary> {
  return apiClient<FindingsSummary>("/api/v1/findings/summary")
}

/**
 * Full detail for one finding. The list comes from GraphQL with a lean row;
 * the panel fetches this on open for the decision content the list omits
 * (description, rule, remediation, confidence, code snippet + highlight).
 */
export async function getFindingDetail(findingId: number): Promise<Finding> {
  const res = await apiClient<{ finding: Finding }>(`/api/v1/findings/${findingId}`)
  return res.finding
}

/** Advisory enrichment for the drawer's Security Brief. */
export interface FindingAdvisory {
  advisory_id: string | null
  cve_id: string | null
  severity: string | null
  /** Full CVSS vector string (e.g. "CVSS:3.1/AV:N/…"). */
  cvss_vector: string | null
  summary: string | null
  description: string | null
  published_at: string | null
  /** Human-readable affected range (e.g. ">= 0, < 0.11.0"). */
  affected_range: string | null
  /** First patched version, when known. */
  fixed_version: string | null
  references: string[]
  epss_percentile?: number | null
  kev?: boolean
  /** CISA KEV detail when the CVE is listed: regulatory due date + ransomware flag. */
  kev_detail?: {
    due_date: string | null
    date_added: string | null
    known_ransomware: boolean
  } | null
}

/**
 * Advisory brief for one finding (summary, CVSS, affected→patched range, dates),
 * lazily fetched on drawer open. Resolves to null when the finding carries no
 * advisory (SAST/secrets/IaC) or the enrichment read fails — the section is
 * purely additive, so it just doesn't render.
 */
export async function getFindingAdvisory(findingId: number): Promise<FindingAdvisory | null> {
  try {
    const res = await apiClient<{ advisory: FindingAdvisory | null }>(
      `/api/v1/findings/${findingId}/advisory`,
    )
    return res.advisory
  } catch {
    return null
  }
}

/** One other repo affected by the same CVE/package (blast-radius drill-down). */
export interface FindingRelated {
  finding_id: string
  repo: string
  severity: string | null
  state: string | null
}

/** Blast-radius drill-down: the other in-scope repos sharing this finding's
 *  CVE/package, fetched on demand when the analyst expands the count. */
export async function getFindingRelated(findingId: number): Promise<FindingRelated[]> {
  try {
    const res = await apiClient<{ related: FindingRelated[] }>(
      `/api/v1/findings/${findingId}/related`,
    )
    return res.related
  } catch {
    return []
  }
}


/** Reasons accepted by the backend. Keep in sync with backend/src/shared/lifecycle.VALID_DISMISS_REASONS. */
export const DISMISS_REASONS = [
  "Fix started",
  "Risk is tolerable",
  "Alert is inaccurate",
  "Vulnerable code is not used",
] as const

export type DismissReason = (typeof DISMISS_REASONS)[number]

/** Dismiss a single finding with a reason and optional comment. */
export async function dismissFinding(
  findingId: number,
  reason: DismissReason,
  comment?: string,
): Promise<{ ok: true }> {
  return apiClient<{ ok: true }>(`/api/v1/findings/${findingId}`, {
    method: "PATCH",
    body: JSON.stringify({ state: "dismissed", dismiss_reason: reason, comment }),
    headers: { "Content-Type": "application/json" },
  })
}

/** Reopen a previously dismissed or deferred finding. */
export async function reopenFinding(findingId: number): Promise<{ ok: true }> {
  return apiClient<{ ok: true }>(`/api/v1/findings/${findingId}`, {
    method: "PATCH",
    body: JSON.stringify({ state: "open" }),
    headers: { "Content-Type": "application/json" },
  })
}

export interface FindingComment {
  id: string
  actor: string | null
  body: string
  created_at: string | null
}

/** List a finding's comments, oldest first. */
export async function listFindingComments(findingId: number): Promise<FindingComment[]> {
  const res = await apiClient<{ comments: FindingComment[] }>(`/api/v1/findings/${findingId}/comments`)
  return res.comments
}

/** Add a free-text comment to a finding. */
export async function addFindingComment(findingId: number, comment: string): Promise<FindingComment> {
  const res = await apiClient<{ comment: FindingComment }>(`/api/v1/findings/${findingId}/comments`, {
    method: "POST",
    body: JSON.stringify({ comment }),
    headers: { "Content-Type": "application/json" },
  })
  return res.comment
}

/** Defer (snooze) a finding — drops it from the open queue until reopened. */
export async function deferFinding(findingId: number): Promise<{ ok: true }> {
  return apiClient<{ ok: true }>(`/api/v1/findings/${findingId}`, {
    method: "PATCH",
    body: JSON.stringify({ state: "deferred" }),
    headers: { "Content-Type": "application/json" },
  })
}

/** Dismiss many findings at once. Throws if `ids` is empty; the backend caps the batch. */
export async function bulkDismissFindings(
  ids: number[],
  reason: DismissReason,
  comment?: string,
): Promise<{ ok: true; updated: number }> {
  if (ids.length === 0) {
    throw new Error("findings-api: bulkDismissFindings requires at least one id")
  }
  return apiClient<{ ok: true; updated: number }>(`/api/v1/findings`, {
    method: "PATCH",
    body: JSON.stringify({ ids, state: "dismissed", dismiss_reason: reason, comment }),
    headers: { "Content-Type": "application/json" },
  })
}

/** Update a finding's assignee. Pass `null` to clear. */
export async function updateFindingAssignee(
  findingId: number,
  assigneeUserId: string | null,
): Promise<{ ok: true; finding: Finding }> {
  const raw = await apiClient<{ ok: true; finding: Finding | null }>(
    `/api/v1/findings/${findingId}`,
    {
      method: "PATCH",
      body: JSON.stringify({ assignee_user_id: assigneeUserId }),
      headers: { "Content-Type": "application/json" },
    },
  )
  if (!raw.finding) {
    throw new Error("findings-api: server returned no finding payload")
  }
  return { ok: raw.ok, finding: raw.finding }
}

export interface AssignableUser {
  id: string
  username: string
  email: string
}

/** Absolute URL for downloading a finding's advisory report (Markdown). */
export function findingReportUrl(findingId: number | string): string {
  return `/api/v1/findings/${findingId}/report.md`
}

/** Absolute URL for downloading a finding's advisory report as a PDF. */
export function findingReportPdfUrl(findingId: number | string): string {
  return `/api/v1/findings/${findingId}/report.pdf`
}

/** Absolute URL for downloading a finding's benign proof-of-concept script. */
export function findingPocUrl(findingId: number | string): string {
  return `/api/v1/findings/${findingId}/poc`
}

/** Search active users for the finding-assignee picker. Empty/null query returns the first `limit`. */
export async function listAssignableUsers(
  q: string | null = null,
  limit = 20,
): Promise<AssignableUser[]> {
  const qs = new URLSearchParams({ limit: String(limit) })
  const trimmed = q?.trim()
  if (trimmed) qs.set("q", trimmed)
  const data = await apiClient<{ users: AssignableUser[] }>(
    `/api/v1/findings/assignable-users?${qs.toString()}`,
  )
  return data.users
}

const FINDINGS_SEARCH_QUERY = `query FindingsSearch(
  $org: String, $severity: String, $scanner: String, $state: String,
  $q: String, $cve: String, $repo: String,
  $sort: String!, $direction: String!,
  $limit: Int!, $cursor: String, $page: Int!,
  $firstSeenAfter: String, $cwe: String, $kev: Boolean,
  $epssMin: Float, $bands: String,
  $assignee: String, $verdict: String
) {
  findings {
    search(
      org: $org, severity: $severity, scanner: $scanner, state: $state,
      q: $q, cve: $cve, repo: $repo,
      sort: $sort, direction: $direction,
      limit: $limit, cursor: $cursor, page: $page,
      firstSeenAfter: $firstSeenAfter, cwe: $cwe, kev: $kev,
      epssMin: $epssMin, bands: $bands,
      assignee: $assignee, verdict: $verdict
    ) {
      findings {
        id scanner severity state title cve package filePath line
        repo orgId createdAt updatedAt epssPercentile kev cwe
        riskScore cvssScore actionBand assigneeUserId verdict ruledOutReason
      }
      nextCursor
      totalCount
      verdictCounts { total confirmed needsVerify possible ruledOut legacy }
    }
  }
}`

export async function listFindings(
  params: ListFindingsParams,
): Promise<FindingsListResponse> {
  if (!params.orgId) {
    throw new Error("findings-api: orgId is required")
  }

  const variables = {
    org: params.orgId,
    severity: params.severity?.length ? params.severity.join(",") : null,
    scanner: params.scanner?.length ? params.scanner.join(",") : null,
    state: params.state?.length ? params.state.join(",") : null,
    q: params.q ?? null,
    cve: params.cve ?? null,
    repo: params.repo ?? null,
    sort: params.sort ?? "severity",
    direction: params.direction ?? "desc",
    limit: params.limit ?? 50,
    cursor: null,
    page: params.page ?? 1,
    firstSeenAfter: params.first_seen_after ?? null,
    cwe: params.cwe ?? null,
    kev: params.kev ?? null,
    epssMin: params.epss_min ?? null,
    bands: params.bands?.length ? params.bands.join(",") : null,
    assignee: params.assignee ?? null,
    verdict: params.verdict ?? null,
  }

  const data = await postGql<GqlFindingsSearchResponse>(
    "FindingsSearch",
    FINDINGS_SEARCH_QUERY,
    variables,
  )
  const r = data.findings.search
  const vc = r.verdictCounts
  const verdict_counts: VerdictCounts | undefined = vc
    ? {
        total: vc.total,
        confirmed: vc.confirmed,
        needs_verify: vc.needsVerify,
        possible: vc.possible,
        ruled_out: vc.ruledOut,
        legacy: vc.legacy,
      }
    : undefined
  return {
    findings: r.findings.map(fromGqlRow),
    next_cursor: r.nextCursor,
    total_count: r.totalCount,
    verdict_counts,
  }
}
