/**
 * TypeScript client for the onboarding wizard REST API.
 *
 * Endpoints:
 *   GET  /api/v1/onboarding/state?org_id=…
 *   POST /api/v1/onboarding/state/step/{step_id}?org_id=…
 */

import { apiClient } from "./api-client.ts"

const BASE = "/api/v1/onboarding"

export type StepId =
  | "connect_source"
  | "pick_repos"
  | "smoke_test"

export interface StepState {
  completed: boolean
  skipped: boolean
  data: Record<string, unknown>
}

export interface OnboardingState {
  dismissed: boolean
  steps: Record<StepId, StepState>
}

export class OnboardingApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = "OnboardingApiError"
    this.status = status
  }
}

export async function getOnboardingState(orgId: string): Promise<OnboardingState> {
  const url = `${BASE}/state?org_id=${encodeURIComponent(orgId)}`
  const payload = await apiClient<{ state: OnboardingState }>(url)
  return payload.state
}

export async function completeStep(
  orgId: string,
  stepId: StepId,
  data: Record<string, unknown> = {},
): Promise<OnboardingState> {
  const url = `${BASE}/state/step/${stepId}?org_id=${encodeURIComponent(orgId)}`
  const payload = await apiClient<{ state: OnboardingState }>(url, {
    method: "POST",
    body: { action: "complete", data },
  })
  return payload.state
}

export async function skipStep(
  orgId: string,
  stepId: StepId,
): Promise<OnboardingState> {
  const url = `${BASE}/state/step/${stepId}?org_id=${encodeURIComponent(orgId)}`
  const payload = await apiClient<{ state: OnboardingState }>(url, {
    method: "POST",
    body: { action: "skip" },
  })
  return payload.state
}

export async function dismissOnboarding(orgId: string, stepId: StepId): Promise<OnboardingState> {
  const url = `${BASE}/state/step/${stepId}?org_id=${encodeURIComponent(orgId)}`
  const payload = await apiClient<{ state: OnboardingState }>(url, {
    method: "POST",
    body: { action: "dismiss" },
  })
  return payload.state
}
