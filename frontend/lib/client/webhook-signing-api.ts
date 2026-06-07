/**
 * TypeScript client for the webhook signing secrets REST API (Phase 44).
 *
 * Endpoints: /api/v1/notification-channels/{id}/signing-secret
 */

import { apiClient } from "./api-client.ts"

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

export async function listSigningSecrets(destId: number): Promise<SigningSecretMeta[]> {
  const data = await apiClient<{ secrets: SigningSecretMeta[] }>(
    `${BASE}/${destId}/signing-secret`,
  )
  return data.secrets ?? []
}

export async function rotateSigningSecret(destId: number): Promise<RotateSecretResponse> {
  return apiClient<RotateSecretResponse>(`${BASE}/${destId}/signing-secret`, {
    method: "POST",
  })
}

export async function revokeSigningSecret(destId: number, version: number): Promise<void> {
  await apiClient<void>(`${BASE}/${destId}/signing-secret/${version}`, {
    method: "DELETE",
  })
}
