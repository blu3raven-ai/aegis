import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Minimal fetch mock
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
// Step progression flow (simulates what the wizard page does)
// ---------------------------------------------------------------------------

test("wizard flow: completing all steps in order sets all steps completed", async () => {
  let stepsCompleted: string[] = []

  const mockPost = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = input.toString()
    const body = JSON.parse(init?.body as string)

    // Extract step id from URL pattern: /state/step/{step_id}
    const match = url.match(/\/step\/([^?]+)/)
    if (match && body.action === "complete") {
      stepsCompleted.push(match[1])
    }

    const state = {
      dismissed: body.action === "dismiss",
      steps: {
        welcome: { completed: true, skipped: false, data: {} },
        connect_source: { completed: stepsCompleted.includes("connect_source"), skipped: false, data: {} },
        smoke_test: { completed: stepsCompleted.includes("smoke_test"), skipped: false, data: {} },
        alerts: { completed: stepsCompleted.includes("alerts"), skipped: false, data: {} },
        policy: { completed: stepsCompleted.includes("policy"), skipped: false, data: {} },
      },
    }
    return new Response(JSON.stringify({ state }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })
  }

  globalThis.fetch = mockPost as unknown as typeof fetch

  const { completeStep, dismissOnboarding } = await loadModule()

  const s1 = await completeStep("example-org", "welcome", {})
  assert.equal(s1.steps.welcome.completed, true)

  const s2 = await completeStep("example-org", "connect_source", { provider: "github" })
  assert.equal(s2.steps.connect_source.completed, true)

  const s3 = await completeStep("example-org", "smoke_test", { findings_count: 3 })
  assert.equal(s3.steps.smoke_test.completed, true)

  const s4 = await completeStep("example-org", "alerts", { destination_id: 7 })
  assert.equal(s4.steps.alerts.completed, true)

  const s5 = await completeStep("example-org", "policy", { policy: "warn_on_high_plus" })
  assert.equal(s5.steps.policy.completed, true)

  const dismissed = await dismissOnboarding("example-org")
  assert.equal(dismissed.dismissed, true)

  assert.deepEqual(stepsCompleted, ["welcome", "connect_source", "smoke_test", "alerts", "policy"])
})

test("wizard flow: skipping a step marks it skipped not completed", async () => {
  const stateWithSkippedSmoke = {
    state: {
      dismissed: false,
      steps: {
        welcome: { completed: true, skipped: false, data: {} },
        connect_source: { completed: true, skipped: false, data: {} },
        smoke_test: { completed: false, skipped: true, data: {} },
        alerts: { completed: false, skipped: false, data: {} },
        policy: { completed: false, skipped: false, data: {} },
      },
    },
  }
  const { mock } = makeFetchMock(stateWithSkippedSmoke)
  globalThis.fetch = mock as unknown as typeof fetch

  const { skipStep } = await loadModule()
  const result = await skipStep("example-org", "smoke_test")

  assert.equal(result.steps.smoke_test.skipped, true)
  assert.equal(result.steps.smoke_test.completed, false)
})

test("wizard resumes at first incomplete step on load", async () => {
  const stateWithPartialProgress = {
    state: {
      dismissed: false,
      steps: {
        welcome: { completed: true, skipped: false, data: {} },
        connect_source: { completed: true, skipped: false, data: {} },
        smoke_test: { completed: false, skipped: false, data: {} }, // <-- should resume here
        alerts: { completed: false, skipped: false, data: {} },
        policy: { completed: false, skipped: false, data: {} },
      },
    },
  }
  const { mock } = makeFetchMock(stateWithPartialProgress)
  globalThis.fetch = mock as unknown as typeof fetch

  const { getOnboardingState } = await loadModule()
  const s = await getOnboardingState("example-org")

  const STEPS = ["welcome", "connect_source", "smoke_test", "alerts", "policy"] as const
  type StepId = typeof STEPS[number]

  const firstIncomplete = STEPS.findIndex(
    (id) => !s.steps[id as StepId].completed && !s.steps[id as StepId].skipped
  )

  assert.equal(firstIncomplete, 2) // smoke_test is index 2
})

test("wizard shows completion when dismissed=true on load", async () => {
  const dismissedState = {
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
  const { mock } = makeFetchMock(dismissedState)
  globalThis.fetch = mock as unknown as typeof fetch

  const { getOnboardingState } = await loadModule()
  const s = await getOnboardingState("example-org")

  assert.equal(s.dismissed, true)
})

test("sidebar should show onboarding entry when dismissed=false", async () => {
  const incompleteState = {
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
  const { mock } = makeFetchMock(incompleteState)
  globalThis.fetch = mock as unknown as typeof fetch

  const { getOnboardingState } = await loadModule()
  const s = await getOnboardingState("example-org")

  // Sidebar logic: show nav item when !onboardingComplete
  const onboardingComplete = s.dismissed
  assert.equal(onboardingComplete, false)
})
