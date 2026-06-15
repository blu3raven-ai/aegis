import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./client.tsx", import.meta.url), "utf8")

test("useBranding fetches /api/v1/branding", () => {
  assert.match(SRC, /apiClient<.*>\("\/api\/v1\/branding"/)
})

test("useBranding falls back to /logo-brand.png when logoDataUrl is null", () => {
  assert.match(SRC, /"\/logo-brand\.png"/)
})

test("useBranding exposes invalidateBrandingCache for write-through", () => {
  assert.match(SRC, /export function invalidateBrandingCache/)
})

test("useBranding shape mirrors useLicense (module-level cache + hook)", () => {
  assert.match(SRC, /export function useBranding/)
  assert.match(SRC, /let cachedBranding/)
})

test("isVendorBranded is true only when name is null", () => {
  assert.match(SRC, /name == null/)
  assert.doesNotMatch(SRC, /=== "Blu3Raven"/)
  assert.doesNotMatch(SRC, /=== 'Blu3Raven'/)
})

test("useBranding exports isVendor in its return shape", () => {
  assert.match(SRC, /isVendor/)
})
