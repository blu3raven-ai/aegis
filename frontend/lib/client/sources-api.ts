/** Client for the polymorphic sources surface (repos, images, cloud) and per-asset detail. */

import { apiClient } from "./api-client.ts"

export interface FindingCounts {
  critical: number
  high: number
  medium: number
  low: number
}

interface CommonSourceFields {
  asset_id: string
  display_name: string | null
  last_scanned_at: string | null
  finding_counts: FindingCounts
}

// ── Per-type blocks ─────────────────────────────────────────────────────────

export interface RepoExtras {
  last_scanned_sha: string | null
  manifest_set_hash: string | null
  scanners_with_coverage: string[]
  coverage_status: "fresh" | "stale" | "never"
  source_url: string | null
  open_finding_count: number
}

export interface RepoSourceSummary extends CommonSourceFields {
  type: "repo"
  repo: RepoExtras
}

export interface ImageExtras {
  image_digest: string | null
  image_name: string | null
  image_tag: string | null
  layer_count: number | null
  size_bytes: number | null
  base_os: string | null
  repos: string[]
}

export interface ImageSourceSummary extends CommonSourceFields {
  type: "image"
  image: ImageExtras
}

export interface CloudExtras {
  provider: string | null
  account_id: string | null
  regions: string[]
}

export interface CloudSourceSummary extends CommonSourceFields {
  type: "cloud"
  cloud: CloudExtras
}

export type SourceSummary = RepoSourceSummary | ImageSourceSummary | CloudSourceSummary

// ── Detail shape ────────────────────────────────────────────────────────────

export interface ScanRunRow {
  scan_id: string
  scanner_type: string
  status: string
  started_at: string
  duration_ms: number | null
  findings_count: number
}

export interface FindingRow {
  id: number
  tool: string
  severity: string | null
  state: string
  identity_key: string
  asset_id: string | null
  first_seen_at: string
  last_seen_at: string
}

interface DetailMixin {
  scan_history: ScanRunRow[]
  active_findings: FindingRow[]
}

export interface RepoSourceDetail extends RepoSourceSummary, DetailMixin {
  default_branch: string | null
}

export interface ImageSourceDetail extends ImageSourceSummary, DetailMixin {}

export interface CloudSourceDetail extends CloudSourceSummary, DetailMixin {}

export type SourceDetail = RepoSourceDetail | ImageSourceDetail | CloudSourceDetail

// ── Legacy flat shapes (back-compat for components) ─────────────────────────

/** Flat repo summary preserving the field names existing components reference. */
export interface RepoSummary {
  repo_id: string                  // = asset_id (UUID)
  asset_id: string                 // = asset_id (UUID); kept for new callers
  org: string                      // derived from display_name "owner/name"
  repo: string                     // derived from display_name "owner/name"
  display_name: string | null
  last_scanned_sha: string | null
  manifest_set_hash: string | null
  last_scanned_at: string | null
  findings_count_by_severity: FindingCounts
  /** True open-finding total across all severities (findings_count_by_severity
   *  keeps only the four ranked buckets, so it can undercount NULL/other). */
  open_finding_count: number
  scanners_with_coverage: string[]
  coverage_status: "fresh" | "stale" | "never"
  source_url: string | null
}

export interface RepoDetail extends RepoSummary {
  scan_history: ScanRunRow[]
  active_findings: FindingRow[]
  default_branch: string | null
}

export interface ImageRow {
  image_digest: string
  image_name: string | null
  image_tag: string | null
  first_seen_at: string
  last_scanned_at: string | null
  finding_counts: FindingCounts
  repos: string[]
  layer_count: number | null
  size_bytes: number | null
  base_os: string | null
}

export interface ImageListResponse {
  images: ImageRow[]
  next_cursor: string | null
  total_count: number
}

// ── Adapters from polymorphic backend → legacy flat shape ───────────────────

function splitOwnerRepo(display: string | null): { org: string; repo: string } {
  if (!display) return { org: "", repo: "" }
  const slash = display.indexOf("/")
  if (slash < 0) return { org: "", repo: display }
  return { org: display.slice(0, slash), repo: display.slice(slash + 1) }
}

function toRepoSummary(s: RepoSourceSummary): RepoSummary {
  const { org, repo } = splitOwnerRepo(s.display_name)
  return {
    repo_id: s.asset_id,
    asset_id: s.asset_id,
    org,
    repo,
    display_name: s.display_name,
    last_scanned_sha: s.repo.last_scanned_sha,
    manifest_set_hash: s.repo.manifest_set_hash,
    last_scanned_at: s.last_scanned_at,
    findings_count_by_severity: s.finding_counts,
    open_finding_count: s.repo.open_finding_count,
    scanners_with_coverage: s.repo.scanners_with_coverage,
    coverage_status: s.repo.coverage_status,
    source_url: s.repo.source_url,
  }
}

function toRepoDetail(s: RepoSourceDetail): RepoDetail {
  return {
    ...toRepoSummary(s),
    scan_history: s.scan_history,
    active_findings: s.active_findings,
    default_branch: s.default_branch,
  }
}

function toImageRow(s: ImageSourceSummary, firstSeen: string): ImageRow {
  return {
    image_digest: s.image.image_digest ?? s.asset_id,
    image_name: s.image.image_name,
    image_tag: s.image.image_tag,
    first_seen_at: firstSeen,
    last_scanned_at: s.last_scanned_at,
    finding_counts: s.finding_counts,
    repos: s.image.repos,
    layer_count: s.image.layer_count,
    size_bytes: s.image.size_bytes,
    base_os: s.image.base_os,
  }
}

// ── GraphQL transport (inlined to keep the test-time module graph tiny) ────

const CSRF_COOKIE_NAME = "__Host-csrf"

function readCsrfCookie(): string | null {
  if (typeof document === "undefined") return null
  for (const pair of document.cookie.split(";").map((p) => p.trim())) {
    const [k, ...rest] = pair.split("=")
    if (k === CSRF_COOKIE_NAME) return rest.join("=")
  }
  return null
}

async function gqlFetch<T>(operationName: string, query: string, variables: Record<string, unknown>): Promise<T> {
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

  const body = (await res.json()) as { data?: T; errors?: { message: string }[] }
  if (body.errors && body.errors.length > 0) {
    throw new Error(body.errors[0].message)
  }
  if (!body.data) {
    throw new Error(`${operationName} returned no data`)
  }
  return body.data
}

// ── GraphQL adapter shape (camelCase wire fields → snake_case TS types) ────

interface GqlFindingCounts {
  critical: number
  high: number
  medium: number
  low: number
}

interface GqlRepoExtras {
  lastScannedSha: string | null
  manifestSetHash: string | null
  scannersWithCoverage: string[]
  coverageStatus: "fresh" | "stale" | "never"
  sourceUrl: string | null
  openFindingCount: number
}

interface GqlImageExtras {
  imageDigest: string | null
  imageName: string | null
  imageTag: string | null
  layerCount: number | null
  sizeBytes: number | null
  baseOs: string | null
  repos: string[]
}

interface GqlRepoSummaryRow {
  type: "repo"
  assetId: string
  displayName: string | null
  lastScannedAt: string | null
  findingCounts: GqlFindingCounts
  repo: GqlRepoExtras
}

interface GqlImageSummaryRow {
  type: "image"
  assetId: string
  displayName: string | null
  lastScannedAt: string | null
  findingCounts: GqlFindingCounts
  image: GqlImageExtras
}

interface GqlScanRunRow {
  scanId: string
  scannerType: string
  status: string
  startedAt: string
  durationMs: number | null
  findingsCount: number
}

interface GqlFindingRow {
  id: number
  tool: string
  severity: string | null
  state: string
  identityKey: string
  assetId: string | null
  firstSeenAt: string
  lastSeenAt: string
}

interface GqlRepoDetail extends GqlRepoSummaryRow {
  scanHistory: GqlScanRunRow[]
  activeFindings: GqlFindingRow[]
  defaultBranch: string | null
}

interface GqlImageDetail extends GqlImageSummaryRow {
  scanHistory: GqlScanRunRow[]
  activeFindings: GqlFindingRow[]
}

type GqlSourceDetail = GqlRepoDetail | GqlImageDetail

const REPO_SUMMARY_FIELDS = `
  type
  assetId
  displayName
  lastScannedAt
  findingCounts { critical high medium low }
  repo {
    lastScannedSha
    manifestSetHash
    scannersWithCoverage
    coverageStatus
    sourceUrl
    openFindingCount
  }
`

const IMAGE_SUMMARY_FIELDS = `
  type
  assetId
  displayName
  lastScannedAt
  findingCounts { critical high medium low }
  image {
    imageDigest
    imageName
    imageTag
    layerCount
    sizeBytes
    baseOs
    repos
  }
`

const SCAN_RUN_FIELDS = `scanId scannerType status startedAt durationMs findingsCount`
const FINDING_ROW_FIELDS = `id tool severity state identityKey assetId firstSeenAt lastSeenAt`

const REPO_SOURCES_QUERY = `
  query RepoSources($sinceDays: Int, $hasCritical: Boolean, $limit: Int!) {
    sources {
      repoSources(sinceDays: $sinceDays, hasCritical: $hasCritical, limit: $limit) {
        sources { ${REPO_SUMMARY_FIELDS} }
        nextCursor
        totalCount
        coverageSummary { total fresh stale never }
      }
    }
  }
`

const IMAGE_SOURCES_QUERY = `
  query ImageSources($cursor: String, $limit: Int!) {
    sources {
      imageSources(cursor: $cursor, limit: $limit) {
        sources { ${IMAGE_SUMMARY_FIELDS} }
        nextCursor
        totalCount
      }
    }
  }
`

const SOURCE_DETAIL_QUERY = `
  query SourceDetail($assetId: ID!) {
    sources {
      source(assetId: $assetId) {
        __typename
        ... on SourceRepoDetail {
          ${REPO_SUMMARY_FIELDS}
          scanHistory { ${SCAN_RUN_FIELDS} }
          activeFindings { ${FINDING_ROW_FIELDS} }
          defaultBranch
        }
        ... on SourceImageDetail {
          ${IMAGE_SUMMARY_FIELDS}
          scanHistory { ${SCAN_RUN_FIELDS} }
          activeFindings { ${FINDING_ROW_FIELDS} }
        }
      }
    }
  }
`

function gqlScanRunToTs(r: GqlScanRunRow): ScanRunRow {
  return {
    scan_id: r.scanId,
    scanner_type: r.scannerType,
    status: r.status,
    started_at: r.startedAt,
    duration_ms: r.durationMs,
    findings_count: r.findingsCount,
  }
}

function gqlFindingToTs(f: GqlFindingRow): FindingRow {
  return {
    id: f.id,
    tool: f.tool,
    severity: f.severity,
    state: f.state,
    identity_key: f.identityKey,
    asset_id: f.assetId,
    first_seen_at: f.firstSeenAt,
    last_seen_at: f.lastSeenAt,
  }
}

function gqlRepoSummaryToTs(r: GqlRepoSummaryRow): RepoSourceSummary {
  return {
    type: "repo",
    asset_id: r.assetId,
    display_name: r.displayName,
    last_scanned_at: r.lastScannedAt,
    finding_counts: r.findingCounts,
    repo: {
      last_scanned_sha: r.repo.lastScannedSha,
      manifest_set_hash: r.repo.manifestSetHash,
      scanners_with_coverage: r.repo.scannersWithCoverage,
      coverage_status: r.repo.coverageStatus,
      source_url: r.repo.sourceUrl,
      open_finding_count: r.repo.openFindingCount,
    },
  }
}

function gqlImageSummaryToTs(r: GqlImageSummaryRow): ImageSourceSummary {
  return {
    type: "image",
    asset_id: r.assetId,
    display_name: r.displayName,
    last_scanned_at: r.lastScannedAt,
    finding_counts: r.findingCounts,
    image: {
      image_digest: r.image.imageDigest,
      image_name: r.image.imageName,
      image_tag: r.image.imageTag,
      layer_count: r.image.layerCount,
      size_bytes: r.image.sizeBytes,
      base_os: r.image.baseOs,
      repos: r.image.repos,
    },
  }
}

// ── List endpoints ─────────────────────────────────────────────────────────

export async function listRepos(filters: {
  org_id?: string
  since_days?: number
  has_critical?: boolean
  limit?: number
} = {}): Promise<RepoSummary[]> {
  // org_id is accepted for back-compat with the old listRepos signature; the
  // backend scopes via the caller's accessible asset_ids and ignores any org
  // hint. Kept here so existing callers don't get a TS error.
  void filters.org_id
  const data = await gqlFetch<{
    sources: {
      repoSources: {
        sources: GqlRepoSummaryRow[]
        nextCursor: string | null
        totalCount: number | null
      }
    }
  }>("RepoSources", REPO_SOURCES_QUERY, {
    sinceDays: filters.since_days ?? null,
    hasCritical: filters.has_critical ?? null,
    limit: filters.limit ?? 100,
  })
  return (data.sources?.repoSources?.sources ?? []).map((s) => toRepoSummary(gqlRepoSummaryToTs(s)))
}

/** Like {@link listRepos} but also returns the backend's total count, so a
 *  caller that caps the page (e.g. limit: 200) can show "first N of M" instead
 *  of presenting the capped page length as the authoritative total. */
/** Fresh/Stale/Never coverage counts over the full repo scope (server-computed,
 *  so the KPI strip stays accurate when the list page is capped). */
export interface CoverageSummary {
  total: number
  fresh: number
  stale: number
  never: number
}

export async function listReposWithCount(filters: {
  since_days?: number
  has_critical?: boolean
  limit?: number
} = {}): Promise<{ repos: RepoSummary[]; totalCount: number | null; coverageSummary: CoverageSummary | null }> {
  const data = await gqlFetch<{
    sources: {
      repoSources: {
        sources: GqlRepoSummaryRow[]
        nextCursor: string | null
        totalCount: number | null
        coverageSummary: CoverageSummary | null
      }
    }
  }>("RepoSources", REPO_SOURCES_QUERY, {
    sinceDays: filters.since_days ?? null,
    hasCritical: filters.has_critical ?? null,
    limit: filters.limit ?? 100,
  })
  const repoSources = data.sources?.repoSources
  return {
    repos: (repoSources?.sources ?? []).map((s) => toRepoSummary(gqlRepoSummaryToTs(s))),
    totalCount: repoSources?.totalCount ?? null,
    coverageSummary: repoSources?.coverageSummary ?? null,
  }
}

export async function getRepo(repoId: string): Promise<RepoDetail | null> {
  const raw = await fetchSourceDetail(repoId)
  if (raw === null || raw.type !== "repo") return null
  return toRepoDetail(raw)
}

export async function listImages(filters: {
  cursor?: string
  limit?: number
} = {}): Promise<ImageListResponse> {
  const data = await gqlFetch<{
    sources: {
      imageSources: {
        sources: GqlImageSummaryRow[]
        nextCursor: string | null
        totalCount: number | null
      }
    }
  }>("ImageSources", IMAGE_SOURCES_QUERY, {
    cursor: filters.cursor ?? null,
    limit: filters.limit ?? 50,
  })
  const summaries = (data.sources?.imageSources?.sources ?? []).map(gqlImageSummaryToTs)
  // first_seen_at isn't part of ImageExtras; reuse last_scanned_at (the only
  // timestamp the new field surfaces). A never-scanned image falls back to "".
  return {
    images: summaries.map((s) => toImageRow(s, s.last_scanned_at ?? "")),
    next_cursor: data.sources?.imageSources?.nextCursor ?? null,
    total_count: data.sources?.imageSources?.totalCount ?? 0,
  }
}

// ── Polymorphic detail (new callers) ───────────────────────────────────────

async function fetchSourceDetail(assetId: string): Promise<SourceDetail | null> {
  const data = await gqlFetch<{
    sources: { source: (GqlSourceDetail & { __typename: string }) | null }
  }>(
    "SourceDetail",
    SOURCE_DETAIL_QUERY,
    { assetId },
  )
  const raw = data.sources?.source
  if (!raw) return null
  if (raw.__typename === "SourceRepoDetail") {
    const repo = raw as GqlRepoDetail
    return {
      ...gqlRepoSummaryToTs(repo),
      scan_history: repo.scanHistory.map(gqlScanRunToTs),
      active_findings: repo.activeFindings.map(gqlFindingToTs),
      default_branch: repo.defaultBranch,
    }
  }
  if (raw.__typename === "SourceImageDetail") {
    const image = raw as GqlImageDetail
    return {
      ...gqlImageSummaryToTs(image),
      scan_history: image.scanHistory.map(gqlScanRunToTs),
      active_findings: image.activeFindings.map(gqlFindingToTs),
    }
  }
  return null
}

export async function getSource(assetId: string): Promise<SourceDetail | null> {
  return fetchSourceDetail(assetId)
}

// ── Scan submission (polymorphic on asset type) ────────────────────────────

export interface ScanSubmission {
  scan_id: string
  repo_id: string
  commit_sha: string
  scanner_types: string[]
  status: string
  submitted_at: string
  submitted_by: string
}

export interface ScanFindingCounts {
  critical: number
  high: number
  medium: number
  low: number
}

export interface ScanVerificationSummary {
  confirmed: number
  needs_verify: number
  possible: number
  ruled_out: number
  legacy: number
  tokens_in: number
  tokens_out: number
  model: string | null
}

export interface ScanDetail {
  scan_id: string
  repo_id: string
  commit_sha: string
  scanner_types: string[]
  status: "queued" | "running" | "completed" | "failed"
  submitted_at: string
  submitted_by: string
  started_at: string | null
  finished_at: string | null
  finding_counts: ScanFindingCounts | null
  error: string | null
  verification_summary?: ScanVerificationSummary | null
}

/**
 * Submit a manual scan. assetId is the universal handle; commitSha is required
 * for repos, imageDigest is optional for images (defaults to the asset's
 * tracked digest), neither applies to cloud (which 501s today).
 */
export async function submitScan(
  assetId: string,
  options: {
    commitSha?: string
    imageDigest?: string
    scannerTypes?: string[]
  } = {},
): Promise<ScanSubmission> {
  const body: Record<string, unknown> = { asset_id: assetId }
  if (options.commitSha) body.commit_sha = options.commitSha
  if (options.imageDigest) body.image_digest = options.imageDigest
  if (options.scannerTypes && options.scannerTypes.length > 0) {
    body.scanner_types = options.scannerTypes
  }
  return apiClient<ScanSubmission>("/api/v1/scans/manual", { method: "POST", body })
}

export async function getScanStatus(scanId: string, orgId?: string): Promise<ScanDetail> {
  const qs = orgId ? `?org_id=${encodeURIComponent(orgId)}` : ""
  return apiClient<ScanDetail>(`/api/v1/scans/${encodeURIComponent(scanId)}${qs}`)
}

// ── Per-connection scan-run history ─────────────────────────────────────────

export interface ConnectionScanRun {
  scanId: string
  assetId: string
  assetName: string
  scannerType: string
  status: string
  startedAt: string | null
  finishedAt: string | null
  durationMs: number | null
  findingsCount: number
  error: string | null
}

const CONNECTION_SCAN_RUNS_QUERY = `
  query ConnectionScanRuns($connectionId: String!, $limit: Int) {
    sources {
      connectionScanRuns(connectionId: $connectionId, limit: $limit) {
        scanId assetId assetName scannerType status
        startedAt finishedAt durationMs findingsCount error
      }
    }
  }
`

/** Full scan-run history across every asset a source connection discovered. */
export async function getConnectionScanRuns(
  connectionId: string,
  limit = 50,
): Promise<ConnectionScanRun[]> {
  const data = await gqlFetch<{ sources: { connectionScanRuns: ConnectionScanRun[] } }>(
    "ConnectionScanRuns",
    CONNECTION_SCAN_RUNS_QUERY,
    { connectionId, limit },
  )
  return data.sources?.connectionScanRuns ?? []
}
