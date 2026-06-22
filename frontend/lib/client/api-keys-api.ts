import { apiClient } from "./api-client.ts"

export interface ApiKey {
  id: number
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

const BASE = "/api/v1/auth/api-keys"

export async function listApiKeys(): Promise<ApiKey[]> {
  const data = await apiClient<{ keys: ApiKey[] }>(BASE, {
    cache: "no-store",
  })
  return data.keys
}

export async function createApiKey(
  payload: { name: string; scopes: string[]; expires_in_days?: number | null },
): Promise<CreatedApiKey> {
  return apiClient<CreatedApiKey>(BASE, {
    method: "POST",
    body: payload,
  })
}

export async function revokeApiKey(id: number): Promise<ApiKey> {
  return apiClient<ApiKey>(`${BASE}/${id}`, {
    method: "DELETE",
  })
}
