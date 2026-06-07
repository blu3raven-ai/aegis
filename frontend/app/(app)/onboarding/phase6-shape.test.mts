import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { existsSync, readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "..", "..", "..")

function read(rel: string): string {
  return readFileSync(join(ROOT, rel), "utf8")
}

describe("Phase 6 onboarding shape", () => {
  it("STEPS array has exactly the 3 new IDs in order", () => {
    const src = read("app/(app)/onboarding/page.tsx")
    assert.match(
      src,
      /STEPS:\s*StepId\[\]\s*=\s*\[\s*"connect_source",\s*"pick_repos",\s*"smoke_test"\s*\]/,
    )
  })

  it("StepId union has only 3 values", () => {
    const src = read("lib/client/onboarding-api.ts")
    assert.ok(src.includes('"connect_source"'))
    assert.ok(src.includes('"pick_repos"'))
    assert.ok(src.includes('"smoke_test"'))
    assert.ok(!src.includes('"welcome"'))
    assert.ok(!src.includes('"alerts"'))
    assert.ok(!src.includes('"policy"'))
  })

  it("WelcomeStep / AlertsStep / PolicyStep deleted", () => {
    assert.ok(!existsSync(join(ROOT, "app/(app)/onboarding/steps/WelcomeStep.tsx")))
    assert.ok(!existsSync(join(ROOT, "app/(app)/onboarding/steps/AlertsStep.tsx")))
    assert.ok(!existsSync(join(ROOT, "app/(app)/onboarding/steps/PolicyStep.tsx")))
  })

  it("PickReposStep exists and exports the component", () => {
    const src = read("app/(app)/onboarding/steps/PickReposStep.tsx")
    assert.ok(src.includes("export function PickReposStep"))
    assert.ok(src.includes("listRepos"))
  })

  it("page.tsx imports PickReposStep", () => {
    const src = read("app/(app)/onboarding/page.tsx")
    assert.ok(src.includes('from "./steps/PickReposStep"'))
  })
})
