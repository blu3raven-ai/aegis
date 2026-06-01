/**
 * TypeScript client for the webhook signing secrets REST API (Phase 44).
 *
 * Endpoints: /api/v1/notification-channels/{id}/signing-secret
 */

export interface SigningSecretMeta {
  id: string
  channel_id: number
  version: number
  status: "active" | "rotating" | "revoked"
  created_at: string
  revoked_at: string | null
}

export interface RotateSecretResponse {
  secret: SigningSecretMeta & { raw: string }
  signing_secret_version: number
  notice: string
}

const BASE = "/api/v1/notification-channels"

class SigningApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = "SigningApiError"
    this.status = status
  }
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init)
  if (!res.ok) {
    const body = await res.text().catch(() => "")
    let detail = body
    try {
      const parsed = JSON.parse(body) as { detail?: string }
      if (parsed.detail) detail = parsed.detail
    } catch {
      // use raw text
    }
    throw new SigningApiError(
      `signing-api: ${res.status} ${res.statusText}${detail ? ` — ${detail}` : ""}`,
      res.status,
    )
  }
  if (res.status === 204) return undefined as unknown as T
  return res.json() as Promise<T>
}

export async function listSigningSecrets(destId: number): Promise<SigningSecretMeta[]> {
  const data = await fetchJson<{ secrets: SigningSecretMeta[] }>(
    `${BASE}/${destId}/signing-secret`,
  )
  return data.secrets ?? []
}

export async function rotateSigningSecret(destId: number): Promise<RotateSecretResponse> {
  return fetchJson<RotateSecretResponse>(`${BASE}/${destId}/signing-secret`, {
    method: "POST",
  })
}

export async function revokeSigningSecret(destId: number, version: number): Promise<void> {
  await fetchJson<void>(`${BASE}/${destId}/signing-secret/${version}`, {
    method: "DELETE",
  })
}
