/**
 * TypeScript client for the SBOM diff GraphQL query.
 *
 * Backend returns a `SbomDiffOrError` union — on the error branch we throw
 * so callers see a single Promise-rejection failure mode.
 */

export interface SbomComponent {
  name: string
  version?: string
  purl?: string
  type?: string
}

export interface SbomVersionChange {
  name: string
  purl?: string
  from_version: string | null
  to_version: string | null
}

export interface SbomDiffResponse {
  added: SbomComponent[]
  removed: SbomComponent[]
  version_changed: SbomVersionChange[]
  unchanged_count: number
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

type GqlSbomDiffResult = {
  __typename: "SbomDiffResult"
  added: Array<{ name: string; version: string; purl: string; type: string }>
  removed: Array<{ name: string; version: string; purl: string; type: string }>
  versionChanged: Array<{
    name: string
    purl: string
    fromVersion: string | null
    toVersion: string | null
  }>
  unchangedCount: number
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
        added { name version purl type }
        removed { name version purl type }
        versionChanged { name purl fromVersion toVersion }
        unchangedCount
      }
      ... on SbomDiffError {
        message
        code
      }
    }
  }
}`

function toComponent(c: { name: string; version: string; purl: string; type: string }): SbomComponent {
  // Strip empty strings so the consumer's optional-field shape stays honest:
  // the GraphQL schema returns "" for absent values; the legacy REST shape
  // omitted the key entirely.
  return {
    name: c.name,
    version: c.version || undefined,
    purl: c.purl || undefined,
    type: c.type || undefined,
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
    })),
    unchanged_count: r.unchangedCount,
  }
}
