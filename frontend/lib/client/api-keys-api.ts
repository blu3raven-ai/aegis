import { apiClient } from "./api-client.ts"
import { ApiClientError } from "./api-client.types.ts"

export interface ApiKey {
  id: number
  org_id: string
  name: string
  prefix: string
  last_four: string
  scopes: string[]
  created_by: string | null
  created_at: string
  last_used_at: string | null
  expires_at: string | null
  revoked_at: string | null
}

export interface CreatedApiKey extends ApiKey {
  token: string
}

export class ApiKeysApiError extends Error {
  constructor(message: string, public status: number) {
    super(message)
    this.name = "ApiKeysApiError"
  }
}

const BASE = "/api/v1/api-keys"

export async function listApiKeys(orgId: string): Promise<ApiKey[]> {
  const data = await apiClient<{ keys: ApiKey[] }>(`${BASE}?org_id=${encodeURIComponent(orgId)}`, {
    cache: "no-store",
  })
  return data.keys
}

export async function createApiKey(
  orgId: string,
  payload: { name: string; scopes: string[]; expires_in_days?: number | null },
): Promise<CreatedApiKey> {
  return apiClient<CreatedApiKey>(BASE, {
    method: "POST",
    body: { ...payload, org_id: orgId },
  })
}

export async function revokeApiKey(id: number, orgId: string): Promise<ApiKey> {
  return apiClient<ApiKey>(`${BASE}/${id}?org_id=${encodeURIComponent(orgId)}`, {
    method: "DELETE",
  })
}
