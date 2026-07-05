/** Client for the per-org bring-your-own LLM verification config.
 *
 * The API key is write-only: GET never returns it (only a `configured` flag),
 * so the UI shows a stored-placeholder and only sends a new key when changed. */

import { apiClient } from "./api-client.ts"
import { ApiClientError } from "./api-client.types.ts"

/** Rough USD-per-1k-token estimate for display-only cost figures; exact provider rates aren't tracked. */
export const APPROX_COST_PER_1K_TOKENS = 0.01

export interface LlmPublicConfig {
  org_id: string
  api_base_url: string
  model: string
  scan_token_budget: number
  daily_token_budget: number
  enabled: boolean
  /** Always true when a row exists; the key itself is never returned. */
  configured: boolean
}

/** PUT payload — includes the secret api_key (never returned on GET). */
export interface LlmConfigUpdate {
  api_key: string
  api_base_url: string
  model: string
  scan_token_budget: number
  daily_token_budget: number
  enabled: boolean
}

export interface LlmDayUsage {
  date: string
  tokens_in: number
  tokens_out: number
  scans: number
}

export interface LlmUsage {
  days: LlmDayUsage[]
  today_used: number
  today_budget: number
  today_remaining: number
}

export interface LlmTestResult {
  ok: boolean
  error?: string
  detail?: string
  status?: number
}

/** Returns null only when no config is set (404). A 403 (no permission) and any
 *  other error propagate — callers must not collapse "forbidden" into "off". */
export async function getLlmConfig(): Promise<LlmPublicConfig | null> {
  try {
    return await apiClient<LlmPublicConfig>("/api/v1/settings/llm")
  } catch (err) {
    if (err instanceof ApiClientError && err.status === 404) {
      return null
    }
    throw err
  }
}

export async function updateLlmConfig(body: LlmConfigUpdate): Promise<LlmPublicConfig> {
  return apiClient<LlmPublicConfig>("/api/v1/settings/llm", { method: "PUT", body })
}

export async function testLlmConnection(): Promise<LlmTestResult> {
  return apiClient<LlmTestResult>("/api/v1/settings/llm/test", { method: "POST" })
}

export async function deleteLlmConfig(): Promise<{ deleted: boolean }> {
  return apiClient<{ deleted: boolean }>("/api/v1/settings/llm", { method: "DELETE" })
}

export async function getLlmUsage(days = 30): Promise<LlmUsage> {
  return apiClient<LlmUsage>(`/api/v1/settings/llm/usage?days=${days}`)
}
