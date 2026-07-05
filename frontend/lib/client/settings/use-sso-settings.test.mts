import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./use-sso-settings.ts", import.meta.url), "utf8")

test("useSsoSettings fetches /api/v1/settings/sso", () => {
  assert.match(SRC, /apiClient<.*>\("\/api\/v1\/settings\/sso"/)
})

test("useSsoSettings exposes save and mutator helpers", () => {
  assert.match(SRC, /export async function saveSsoSettings/)
  assert.match(SRC, /export async function generateSamlKeypair/)
  assert.match(SRC, /export async function refreshSamlMetadata/)
})

test("SsoSettings interface includes the derived URLs and 'set' booleans", () => {
  for (const field of [
    "samlAcsUrl",
    "samlSpMetadataUrl",
    "samlSpPrivateKeySet",
    "oidcClientSecretSet",
    "oidcRedirectUri",
  ]) {
    assert.match(SRC, new RegExp(`${field}:`))
  }
})
