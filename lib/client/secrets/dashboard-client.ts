import { SECRETS_API } from "@/lib/shared/api-paths"
import { readJsonResponse } from "@/lib/shared/client-json"
import type {
  SecretFinding,
  SecretReviewStatus,
  SecretScanRun,
  SecretsHealthResponse,
  SecretsInsightsResponse,
  SecretsReviewQueueResponse,
} from "@/lib/shared/secrets/types"

export interface MultiOrgStatus {
  orgs: Array<{ org: string; active: boolean; runId: string | null }>
  anyActive: boolean
  totalOrgs: number
}

export interface RunsResponse {
  latest?: SecretScanRun
  runs?: SecretScanRun[]
  lastCompleted?: SecretScanRun
  multiOrgStatus?: MultiOrgStatus
  error?: string
}

export interface StartRunsResponse {
  runs?: Array<{ org: string; runId: string }>
  message?: string
  error?: string
}

export interface CancelRunsResponse {
  ok?: boolean
  results?: Array<{ org: string; cancelled: boolean; error?: string }>
  message?: string
  error?: string
}

export interface CodePreviewResponse {
  organization: string
  repository: string
  filePath: string
  commit: string
  commitDate?: string | null
  commitIsHead?: boolean
  line: number
  githubUrl: string
  lines: Array<{ number: number; content: string; highlighted: boolean }>
  error?: string
}

export interface ReviewUpdatePayload {
  fingerprint: string
  status: SecretReviewStatus
  secretIdentity?: string | null
  scope?: "secret" | "occurrence"
  repository?: string | null
  source?: string | null
  detector?: string | null
  filePath?: string | null
  line?: number | null
  commit?: string | null
}

async function fetchJson<T>(input: string, init?: RequestInit): Promise<{ ok: boolean; payload: T }> {
  const response = await fetch(input, init)
  const payload = await readJsonResponse<T>(response)
  return { ok: response.ok, payload }
}

export function fetchSecretsReviewQueue(orgQuery: string) {
  return fetchJson<SecretsReviewQueueResponse>(`${SECRETS_API.reviewQueue}?${orgQuery}`)
}

export function fetchSecretsInsights(
  orgQuery: string,
  filters?: { source?: string; organization?: string }
) {
  const params = new URLSearchParams(orgQuery)
  if (filters?.source) params.set("source", filters.source)
  if (filters?.organization) params.set("filterOrg", filters.organization)
  return fetchJson<SecretsInsightsResponse>(`${SECRETS_API.insights}?${params.toString()}`)
}

export function fetchSecretsHealth(orgQuery: string) {
  return fetchJson<SecretsHealthResponse>(`${SECRETS_API.health}?${orgQuery}`)
}

export function fetchSecretsRuns(orgQuery: string) {
  return fetchJson<RunsResponse>(`${SECRETS_API.runs}?${orgQuery}`)
}

export function startSecretsRuns(orgQuery: string, mode?: "full" | "incremental", scanDepth?: "light" | "deep" | "ai_enhanced") {
  const params = new URLSearchParams()
  if (mode) params.set("mode", mode)
  if (scanDepth) params.set("scanDepth", scanDepth)
  const qs = params.toString()
  const url = qs
    ? `${SECRETS_API.runsStart}?${orgQuery}&${qs}`
    : `${SECRETS_API.runsStart}?${orgQuery}`
  return fetchJson<StartRunsResponse>(url, { method: "POST" })
}

export function cancelSecretsRuns(orgQuery: string) {
  return fetchJson<CancelRunsResponse>(`${SECRETS_API.runsCancel}?${orgQuery}`, { method: "POST" })
}

export function fetchSecretsCodePreview(finding: SecretFinding) {
  const params = new URLSearchParams({
    org: finding.organization,
    repo: finding.repository,
    fingerprint: finding.fingerprint,
  })
  if (finding.commit) params.set("commit", finding.commit)
  if (finding.filePath) params.set("filePath", finding.filePath)
  if (typeof finding.line === "number") params.set("line", String(finding.line))
  return fetchJson<CodePreviewResponse>(`${SECRETS_API.codePreview}?${params.toString()}`)
}

export function applySecretsReview(org: string, updates: ReviewUpdatePayload[]) {
  return fetchJson<{ ok?: boolean; error?: string }>(SECRETS_API.findingsReview, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ org, updates }),
  })
}

