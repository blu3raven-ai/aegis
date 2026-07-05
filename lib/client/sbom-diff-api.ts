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
  from_hash: string
  to_hash: string
}

export async function diffSbomsByRepo(params: RepoDiffParams): Promise<SbomDiffResponse> {
  const qs = new URLSearchParams({
    repo_id: params.repo_id,
    from_hash: params.from_hash,
    to_hash: params.to_hash,
  })
  const res = await fetch(`/api/v1/sboms/diff?${qs.toString()}`)
  if (!res.ok) {
    const text = await res.text().catch(() => "")
    throw new Error(`sbom-diff-api: ${res.status} ${res.statusText} — ${text}`)
  }
  return res.json() as Promise<SbomDiffResponse>
}
