import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Minimal fetch mock (same shape as destinations-api.test.ts)
// ---------------------------------------------------------------------------

interface FetchCall {
  url: string
  init?: RequestInit
}

function makeFetchMock(body: unknown, status = 200) {
  const calls: FetchCall[] = []
  const mock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    calls.push({ url: input.toString(), init })
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

async function loadModule() {
  return import("../../lib/client/onboarding-api.ts")
}

// ---------------------------------------------------------------------------
// getOnboardingState
// ---------------------------------------------------------------------------

test("getOnboardingState builds correct URL with org_id", async () => {
  const statePayload = {
    state: {
      dismissed: false,
      steps: {
        welcome: { completed: false, skipped: false, data: {} },
        connect_source: { completed: false, skipped: false, data: {} },
        smoke_test: { completed: false, skipped: false, data: {} },
        alerts: { completed: false, skipped: false, data: {} },
        policy: { completed: false, skipped: false, data: {} },
      },
    },
  }
  const { mock, calls } = makeFetchMock(statePayload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { getOnboardingState } = await loadModule()
  const result = await getOnboardingState("example-org")

  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/onboarding/state")
  assert.equal(url.searchParams.get("org_id"), "example-org")
  assert.equal(result.dismissed, false)
})

test("getOnboardingState returns dismissed state correctly", async () => {
  const statePayload = {
    state: {
      dismissed: true,
      steps: {
        welcome: { completed: true, skipped: false, data: {} },
        connect_source: { completed: true, skipped: false, data: {} },
        smoke_test: { completed: true, skipped: false, data: {} },
        alerts: { completed: true, skipped: false, data: {} },
        policy: { completed: true, skipped: false, data: {} },
      },
    },
  }
  const { mock } = makeFetchMock(statePayload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { getOnboardingState } = await loadModule()
  const result = await getOnboardingState("example-org")

  assert.equal(result.dismissed, true)
})

// ---------------------------------------------------------------------------
// completeStep
// ---------------------------------------------------------------------------

test("completeStep sends POST with action=complete and data payload", async () => {
  const statePayload = {
    state: {
      dismissed: false,
      steps: {
        welcome: { completed: true, skipped: false, data: {} },
        connect_source: { completed: false, skipped: false, data: {} },
        smoke_test: { completed: false, skipped: false, data: {} },
        alerts: { completed: false, skipped: false, data: {} },
        policy: { completed: false, skipped: false, data: {} },
      },
    },
  }
  const { mock, calls } = makeFetchMock(statePayload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { completeStep } = await loadModule()
  const result = await completeStep("example-org", "welcome", {})

  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/onboarding/state/step/welcome")
  assert.equal(url.searchParams.get("org_id"), "example-org")
  const body = JSON.parse(calls[0].init?.body as string)
  assert.equal(body.action, "complete")
  assert.deepEqual(body.data, {})
  assert.equal(result.steps.welcome.completed, true)
})

test("completeStep passes data payload in request body", async () => {
  const statePayload = {
    state: {
      dismissed: false,
      steps: {
        welcome: { completed: false, skipped: false, data: {} },
        connect_source: { completed: true, skipped: false, data: { provider: "github" } },
        smoke_test: { completed: false, skipped: false, data: {} },
        alerts: { completed: false, skipped: false, data: {} },
        policy: { completed: false, skipped: false, data: {} },
      },
    },
  }
  const { mock, calls } = makeFetchMock(statePayload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { completeStep } = await loadModule()
  await completeStep("example-org", "connect_source", { provider: "github" })

  const body = JSON.parse(calls[0].init?.body as string)
  assert.deepEqual(body.data, { provider: "github" })
})

// ---------------------------------------------------------------------------
// skipStep
// ---------------------------------------------------------------------------

test("skipStep sends POST with action=skip", async () => {
  const statePayload = {
    state: {
      dismissed: false,
      steps: {
        welcome: { completed: true, skipped: false, data: {} },
        connect_source: { completed: false, skipped: false, data: {} },
        smoke_test: { completed: false, skipped: true, data: {} },
        alerts: { completed: false, skipped: false, data: {} },
        policy: { completed: false, skipped: false, data: {} },
      },
    },
  }
  const { mock, calls } = makeFetchMock(statePayload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { skipStep } = await loadModule()
  const result = await skipStep("example-org", "smoke_test")

  const body = JSON.parse(calls[0].init?.body as string)
  assert.equal(body.action, "skip")
  assert.equal(result.steps.smoke_test.skipped, true)
})

// ---------------------------------------------------------------------------
// dismissOnboarding
// ---------------------------------------------------------------------------

test("dismissOnboarding sends action=dismiss on policy step", async () => {
  const statePayload = {
    state: {
      dismissed: true,
      steps: {
        welcome: { completed: true, skipped: false, data: {} },
        connect_source: { completed: true, skipped: false, data: {} },
        smoke_test: { completed: true, skipped: false, data: {} },
        alerts: { completed: true, skipped: false, data: {} },
        policy: { completed: true, skipped: false, data: {} },
      },
    },
  }
  const { mock, calls } = makeFetchMock(statePayload)
  globalThis.fetch = mock as unknown as typeof fetch

  const { dismissOnboarding } = await loadModule()
  const result = await dismissOnboarding("example-org")

  const body = JSON.parse(calls[0].init?.body as string)
  assert.equal(body.action, "dismiss")
  assert.equal(result.dismissed, true)
})

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

test("getOnboardingState throws on non-ok response", async () => {
  const { mock } = makeFetchMock({ detail: "not found" }, 404)
  globalThis.fetch = mock as unknown as typeof fetch

  const { getOnboardingState } = await loadModule()
  await assert.rejects(() => getOnboardingState("example-org"), /404/)
})
