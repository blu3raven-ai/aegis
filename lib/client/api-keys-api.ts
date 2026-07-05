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

async function _request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { cache: "no-store", ...init })
  if (!res.ok) {
    const text = await res.text().catch(() => "")
    throw new ApiKeysApiError(`api-keys: ${res.status} ${res.statusText} — ${text}`, res.status)
  }
  return res.json() as Promise<T>
}

export async function listApiKeys(orgId: string): Promise<ApiKey[]> {
  const data = await _request<{ keys: ApiKey[] }>(`${BASE}?org_id=${encodeURIComponent(orgId)}`)
  return data.keys
}

export async function createApiKey(
  orgId: string,
  payload: { name: string; scopes: string[]; expires_in_days?: number | null },
): Promise<CreatedApiKey> {
  return _request<CreatedApiKey>(BASE, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...payload, org_id: orgId }),
  })
}

export async function revokeApiKey(id: number, orgId: string): Promise<ApiKey> {
  return _request<ApiKey>(`${BASE}/${id}?org_id=${encodeURIComponent(orgId)}`, {
    method: "DELETE",
  })
}
