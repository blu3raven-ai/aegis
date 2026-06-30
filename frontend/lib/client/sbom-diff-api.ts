/**
 * TypeScript client for the SBOM diff GraphQL query.
 *
 * Backend returns a `SbomDiffOrError` union — on the error branch we throw
 * so callers see a single Promise-rejection failure mode.
 */
import type { LicenseCategory } from "@/lib/sbom/license-category"

export interface VulnCounts {
  critical: number
  high: number
  medium: number
  low: number
  total: number
}

export interface SbomComponent {
  name: string
  version?: string
  purl?: string
  type?: string
  /** Open findings on the to-side asset for this package (current state). */
  current_findings?: VulnCounts
  /** OSV advisories affecting this exact version (introduced on add / dropped on remove). */
  known_vulns?: VulnCounts
}

export interface SbomVersionChange {
  name: string
  purl?: string
  from_version: string | null
  to_version: string | null
  /** OSV advisory set-delta between the two versions. */
  resolved?: VulnCounts
  introduced?: VulnCounts
  still_vulnerable?: VulnCounts
  current_findings?: VulnCounts
  /** License before/after the bump + risk categories — a change is a compliance event. */
  from_license?: string | null
  to_license?: string | null
  from_license_category?: LicenseCategory | null
  to_license_category?: LicenseCategory | null
}

export interface SbomDiffResponse {
  added: SbomComponent[]
  removed: SbomComponent[]
  version_changed: SbomVersionChange[]
  unchanged_count: number
  /** False when the OSV mirror is empty or the diff was too large to re-match —
   *  render the resolved/introduced/dropped deltas as unavailable, not zero. */
  remediation_signal_available: boolean
  /** True totals before the node lists were capped, and a flag when any was —
   *  use these for the headline counts so a capped page isn't shown as the total. */
  added_count: number
  removed_count: number
  version_changed_count: number
  truncated: boolean
}

export interface RepoDiffParams {
  repo_id: string
  from_run_id: string
  to_run_id: string
}

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

type GqlCounts = { critical: number; high: number; medium: number; low: number; total: number }

type GqlDiffComponent = {
  name: string
  version: string
  purl: string
  type: string
  currentFindings: GqlCounts
  knownVulns: GqlCounts
}

type GqlSbomDiffResult = {
  __typename: "SbomDiffResult"
  added: GqlDiffComponent[]
  removed: GqlDiffComponent[]
  versionChanged: Array<{
    name: string
    purl: string
    fromVersion: string | null
    toVersion: string | null
    resolved: GqlCounts
    introduced: GqlCounts
    stillVulnerable: GqlCounts
    currentFindings: GqlCounts
    fromLicense: string | null
    toLicense: string | null
    fromLicenseCategory: string | null
    toLicenseCategory: string | null
  }>
  unchangedCount: number
  remediationSignalAvailable: boolean
  addedCount: number
  removedCount: number
  versionChangedCount: number
  truncated: boolean
}

type GqlSbomDiffError = {
  __typename: "SbomDiffError"
  message: string
  code: string
}

interface GqlSbomDiffResponse {
  sbom: {
    diff: GqlSbomDiffResult | GqlSbomDiffError
  }
}

const SBOM_DIFF_QUERY = `query SbomDiff(
  $repoId: String,
  $fromRunId: String,
  $toRunId: String,
  $imageDigestFrom: String,
  $imageDigestTo: String
) {
  sbom {
    diff(
      repoId: $repoId,
      fromRunId: $fromRunId,
      toRunId: $toRunId,
      imageDigestFrom: $imageDigestFrom,
      imageDigestTo: $imageDigestTo
    ) {
      __typename
      ... on SbomDiffResult {
        added { name version purl type currentFindings { critical high medium low total } knownVulns { critical high medium low total } }
        removed { name version purl type currentFindings { critical high medium low total } knownVulns { critical high medium low total } }
        versionChanged {
          name purl fromVersion toVersion
          fromLicense toLicense fromLicenseCategory toLicenseCategory
          resolved { critical high medium low total }
          introduced { critical high medium low total }
          stillVulnerable { critical high medium low total }
          currentFindings { critical high medium low total }
        }
        unchangedCount
        remediationSignalAvailable
        addedCount
        removedCount
        versionChangedCount
        truncated
      }
      ... on SbomDiffError {
        message
        code
      }
    }
  }
}`

function counts(c: GqlCounts): VulnCounts {
  return { critical: c.critical, high: c.high, medium: c.medium, low: c.low, total: c.total }
}

function toComponent(c: GqlDiffComponent): SbomComponent {
  // Strip empty strings so the consumer's optional-field shape stays honest:
  // the GraphQL schema returns "" for absent values; the legacy REST shape
  // omitted the key entirely.
  return {
    name: c.name,
    version: c.version || undefined,
    purl: c.purl || undefined,
    type: c.type || undefined,
    current_findings: counts(c.currentFindings),
    known_vulns: counts(c.knownVulns),
  }
}

export async function diffSbomsByRepo(params: RepoDiffParams): Promise<SbomDiffResponse> {
  const data = await gqlFetch<GqlSbomDiffResponse>("SbomDiff", SBOM_DIFF_QUERY, {
    repoId: params.repo_id,
    fromRunId: params.from_run_id,
    toRunId: params.to_run_id,
    imageDigestFrom: null,
    imageDigestTo: null,
  })

  const r = data.sbom.diff
  if (r.__typename === "SbomDiffError") {
    throw new Error(r.message)
  }

  return {
    added: r.added.map(toComponent),
    removed: r.removed.map(toComponent),
    version_changed: r.versionChanged.map((v) => ({
      name: v.name,
      purl: v.purl || undefined,
      from_version: v.fromVersion,
      to_version: v.toVersion,
      resolved: counts(v.resolved),
      introduced: counts(v.introduced),
      still_vulnerable: counts(v.stillVulnerable),
      current_findings: counts(v.currentFindings),
      from_license: v.fromLicense,
      to_license: v.toLicense,
      from_license_category: (v.fromLicenseCategory as LicenseCategory | null) ?? null,
      to_license_category: (v.toLicenseCategory as LicenseCategory | null) ?? null,
    })),
    unchanged_count: r.unchangedCount,
    remediation_signal_available: r.remediationSignalAvailable,
    added_count: r.addedCount,
    removed_count: r.removedCount,
    version_changed_count: r.versionChangedCount,
    truncated: r.truncated,
  }
}
