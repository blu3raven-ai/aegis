import { describe, it } from "node:test"
import assert from "node:assert/strict"
import {
  CATEGORY_SCANNERS,
  SCANNER_LABELS,
  SCANNER_DESCRIPTIONS,
  type ScannerType,
} from "./sources-types.ts"

// The frontend CATEGORY_SCANNERS must mirror the backend SCANNERS_BY_CATEGORY
// (backend/src/sources/triggers.py). Keep these in sync — a drift here means
// the settings UI offers scanners the backend won't run, or hides ones it will.
describe("CATEGORY_SCANNERS mirrors the backend mapping", () => {
  it("code repositories run dependencies, secret, code, IaC, agent, and deep-audit scanning", () => {
    assert.deepEqual(CATEGORY_SCANNERS["code-repositories"], [
      "dependencies_scanning",
      "secret_scanning",
      "code_scanning",
      "iac_scanning",
      "agent_scanning",
      "deep_audit",
    ])
  })

  it("container registries run only container scanning", () => {
    assert.deepEqual(CATEGORY_SCANNERS["container-registry"], ["container_scanning"])
  })

  it("categories without scanners are empty (selector hidden)", () => {
    assert.deepEqual(CATEGORY_SCANNERS["cloud-infrastructure"], [])
    assert.deepEqual(CATEGORY_SCANNERS["ci-systems"], [])
  })
})

describe("scanner metadata is complete", () => {
  it("every scanner used by a category has a label and description", () => {
    const used = new Set<ScannerType>()
    for (const list of Object.values(CATEGORY_SCANNERS)) {
      for (const s of list) used.add(s)
    }
    for (const scanner of used) {
      assert.ok(SCANNER_LABELS[scanner], `missing label for ${scanner}`)
      assert.ok(SCANNER_DESCRIPTIONS[scanner], `missing description for ${scanner}`)
    }
  })
})
