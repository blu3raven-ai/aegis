/**
 * TypeScript client for the chain-graph REST API (Phase 3b).
 *
 * All endpoints are served from the Next.js API proxy, which forwards to the
 * FastAPI backend. Mirrors the pattern used in dependencies-client.ts.
 */

export interface ChainEdge {
  id: number
  chain_id: string
  source_finding_id: number
  target_finding_id: number
  edge_type: string
  confidence: number
  provenance_rule: string
  created_at: string
}

export interface Chain {
  id: string
  org_id: string
  chain_type: string
  severity: "critical" | "high" | "medium" | "low" | string
  status: "open" | "acknowledged" | "resolved" | string
  created_at: string
  last_updated_at: string
  ai_explanation_id?: string | null
}

export interface ChainDetail extends Chain {
  edges: ChainEdge[]
}

export interface ListChainsResponse {
  chains: Chain[]
  error?: string
}

export interface GetChainResponse {
  chain?: ChainDetail
  error?: string
}

export interface FindingChainsResponse {
  chains: Chain[]
  error?: string
}

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url)
  if (!res.ok) {
    const text = await res.text().catch(() => "")
    throw new Error(`chains-api: ${res.status} ${res.statusText} — ${text}`)
  }
  return res.json() as Promise<T>
}

export async function listChains(
  orgId: string,
  opts: { severity?: string; chainType?: string; limit?: number } = {},
): Promise<ListChainsResponse> {
  const params = new URLSearchParams({ org_id: orgId })
  if (opts.severity) params.set("severity", opts.severity)
  if (opts.chainType) params.set("chain_type", opts.chainType)
  if (opts.limit != null) params.set("limit", String(opts.limit))
  return fetchJson<ListChainsResponse>(`/api/v1/chains?${params.toString()}`)
}

export async function getChain(chainId: string): Promise<ChainDetail> {
  return fetchJson<ChainDetail>(`/api/v1/chains/${chainId}`)
}

export async function getChainsForFinding(findingId: number): Promise<FindingChainsResponse> {
  return fetchJson<FindingChainsResponse>(`/api/v1/findings/${findingId}/chains`)
}
