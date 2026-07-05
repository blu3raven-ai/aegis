/** Client for the per-org Argus verification connection (OAuth). */

import { apiClient } from "./api-client.ts"

export interface ArgusConnection {
  /** Base URL of the Argus verification service. */
  endpoint: string
  /** OAuth2 token endpoint of the org's IdP. */
  token_endpoint: string
  /** OAuth2 client id. */
  client_id: string
  /** Whether verification is switched on. */
  enabled: boolean
  /** True when an endpoint is configured and enabled. */
  connected: boolean
}

/** PUT payload — includes the secret refresh token (never returned on GET). */
export interface ArgusConnectionUpdate {
  endpoint: string
  token_endpoint: string
  client_id: string
  refresh_token: string
  enabled: boolean
}

export interface ArgusTestResult {
  ok: boolean
  error?: string
  detail?: string
}

export async function getArgusConnection(): Promise<ArgusConnection> {
  return apiClient<ArgusConnection>("/api/v1/settings/argus")
}

export async function updateArgusConnection(
  body: ArgusConnectionUpdate,
): Promise<ArgusConnection> {
  return apiClient<ArgusConnection>("/api/v1/settings/argus", { method: "PUT", body })
}

/** Mint a token and ping Argus `/health` to prove the OAuth exchange + reachability. */
export async function testArgusConnection(): Promise<ArgusTestResult> {
  return apiClient<ArgusTestResult>("/api/v1/settings/argus/test", { method: "POST" })
}

export async function disconnectArgus(): Promise<{ deleted: boolean }> {
  return apiClient<{ deleted: boolean }>("/api/v1/settings/argus", { method: "DELETE" })
}
