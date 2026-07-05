import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./use-org-settings.ts", import.meta.url), "utf8")

test("useOrgSettings PATCHes /api/v1/settings/organisations for name updates", () => {
  assert.match(SRC, /apiClient<.*>\("\/api\/v1\/settings\/organisations"/)
})

test("useOrgSettings exposes saveOrgSettings, setOrgLogo, clearOrgLogo", () => {
  assert.match(SRC, /export async function saveOrgSettings/)
  assert.match(SRC, /export async function setOrgLogo/)
  assert.match(SRC, /export async function clearOrgLogo/)
})

test("useOrgSettings invalidates the branding cache after mutations", () => {
  assert.match(SRC, /invalidateBrandingCache/)
})

test("useOrgSettings includes the org settings field shape", () => {
  for (const field of ["name", "logoDataUrl"]) {
    assert.match(SRC, new RegExp(`${field}:`))
  }
})

test("useOrgSettings does not include dropped fields", () => {
  for (const field of ["subtitle", "defaultTimezone", "securityContactEmail"]) {
    assert.doesNotMatch(SRC, new RegExp(`${field}:`))
  }
})
