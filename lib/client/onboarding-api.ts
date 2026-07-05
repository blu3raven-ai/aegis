/**
 * TypeScript client for the onboarding wizard REST API.
 *
 * Endpoints:
 *   GET  /api/v1/onboarding/state?org_id=…
 *   POST /api/v1/onboarding/state/step/{step_id}?org_id=…
 */

const BASE = "/api/v1/onboarding"

export type StepId =
  | "welcome"
  | "connect_source"
  | "smoke_test"
  | "alerts"
  | "policy"

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
    throw new OnboardingApiError(
      `onboarding-api: ${res.status} ${res.statusText}${detail ? ` — ${detail}` : ""}`,
      res.status,
    )
  }
  return res.json() as Promise<T>
}

export async function getOnboardingState(orgId: string): Promise<OnboardingState> {
  const url = `${BASE}/state?org_id=${encodeURIComponent(orgId)}`
  const payload = await fetchJson<{ state: OnboardingState }>(url)
  return payload.state
}

export async function completeStep(
  orgId: string,
  stepId: StepId,
  data: Record<string, unknown> = {},
): Promise<OnboardingState> {
  const url = `${BASE}/state/step/${stepId}?org_id=${encodeURIComponent(orgId)}`
  const payload = await fetchJson<{ state: OnboardingState }>(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "complete", data }),
  })
  return payload.state
}

export async function skipStep(
  orgId: string,
  stepId: StepId,
): Promise<OnboardingState> {
  const url = `${BASE}/state/step/${stepId}?org_id=${encodeURIComponent(orgId)}`
  const payload = await fetchJson<{ state: OnboardingState }>(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "skip" }),
  })
  return payload.state
}

export async function dismissOnboarding(orgId: string): Promise<OnboardingState> {
  const url = `${BASE}/state/step/policy?org_id=${encodeURIComponent(orgId)}`
  const payload = await fetchJson<{ state: OnboardingState }>(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "dismiss" }),
  })
  return payload.state
}
