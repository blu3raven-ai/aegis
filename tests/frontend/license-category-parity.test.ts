/**
 * Parity guard: the frontend license classifier (license-category.ts) must agree
 * with the authoritative backend classifier (backend/src/sbom/licenses.py) on a
 * shared fixture set. The Python side asserts the SAME fixtures
 * (backend/src/tests/test_license_classifier_parity.py), so if either
 * implementation drifts, its own test fails — the per-repo table (client-parsed)
 * and the estate explorer (backend-classified) can't silently diverge.
 */
import test from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

import { classifyLicensesRaw } from "../../frontend/lib/sbom/license-category.ts"

interface Fixture {
  desc: string
  licenses: unknown[]
  category: string
}

const fixtures: Fixture[] = JSON.parse(
  readFileSync(fileURLToPath(new URL("../fixtures/license-classification.json", import.meta.url)), "utf8"),
)

test("frontend classifyLicensesRaw matches the shared backend fixture", () => {
  assert.ok(fixtures.length >= 20, "fixture set should be substantial")
  for (const fx of fixtures) {
    assert.equal(
      classifyLicensesRaw(fx.licenses),
      fx.category,
      `frontend classifier drifted on: ${fx.desc} (${JSON.stringify(fx.licenses)})`,
    )
  }
})
