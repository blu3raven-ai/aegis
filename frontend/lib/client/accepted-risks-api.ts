import { apiClient } from "./api-client.ts"
import { ApiClientError } from "./api-client.types.ts"

const BASE = "/api/v1/accepted-risks"

export type ApiResult<T> = { ok: true; data: T } | { ok: false; error: string }

export interface AcceptedRisk {
  id: number
  assetId: string | null
  sourceConnectionId: string | null
  statement: string
  pathGlob: string | null
  ruleId: string | null
  scanner: string | null
  enabled: boolean
}

// Raw snake_case shape returned by the backend.
interface RawAcceptedRisk {
  id: number
  asset_id: string | null
  source_connection_id: string | null
  statement: string
  path_glob: string | null
  rule_id: string | null
  scanner: string | null
  enabled: boolean
  created_by?: string | null
}

function fromApi(raw: RawAcceptedRisk): AcceptedRisk {
  return {
    id: raw.id,
    assetId: raw.asset_id,
    sourceConnectionId: raw.source_connection_id,
    statement: raw.statement,
    pathGlob: raw.path_glob,
    ruleId: raw.rule_id,
    scanner: raw.scanner,
    enabled: raw.enabled,
  }
}

async function request<T>(
  path: string,
  init?: { method?: string; body?: unknown },
): Promise<ApiResult<T>> {
  try {
    const data = await apiClient<T>(`${BASE}${path}`, {
      method: init?.method,
      body: init?.body,
      cache: "no-store",
    })
    return { ok: true, data }
  } catch (error) {
    if (error instanceof ApiClientError) {
      const body = error.body as { error?: string; message?: string; detail?: string } | null
      const msg = body?.error ?? body?.message ?? body?.detail
      return { ok: false, error: msg ?? `Request failed (${error.status}).` }
    }
    return { ok: false, error: error instanceof Error ? error.message : "Request failed." }
  }
}

export async function listAcceptedRisks(): Promise<
  ApiResult<{ acceptedRisks: AcceptedRisk[] }>
> {
  const result = await request<{ acceptedRisks: RawAcceptedRisk[] }>("")
  if (!result.ok) return result
  return { ok: true, data: { acceptedRisks: result.data.acceptedRisks.map(fromApi) } }
}

export interface CreateAcceptedRiskInput {
  statement: string
  asset_id?: string | null
  source_connection_id?: string | null
  path_glob?: string | null
  rule_id?: string | null
  scanner?: string | null
  enabled?: boolean
}

export async function createAcceptedRisk(
  input: CreateAcceptedRiskInput,
): Promise<ApiResult<{ acceptedRisk: AcceptedRisk }>> {
  const result = await request<{ acceptedRisk: RawAcceptedRisk }>("", {
    method: "POST",
    body: input,
  })
  if (!result.ok) return result
  return { ok: true, data: { acceptedRisk: fromApi(result.data.acceptedRisk) } }
}

export type UpdateAcceptedRiskInput = Partial<CreateAcceptedRiskInput>

export async function updateAcceptedRisk(
  id: number,
  input: UpdateAcceptedRiskInput,
): Promise<ApiResult<{ acceptedRisk: AcceptedRisk }>> {
  const result = await request<{ acceptedRisk: RawAcceptedRisk }>(`/${id}`, {
    method: "PATCH",
    body: input,
  })
  if (!result.ok) return result
  return { ok: true, data: { acceptedRisk: fromApi(result.data.acceptedRisk) } }
}

export async function deleteAcceptedRisk(
  id: number,
): Promise<ApiResult<{ deleted: boolean }>> {
  return request<{ deleted: boolean }>(`/${id}`, { method: "DELETE" })
}
