import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const src = readFileSync(
  fileURLToPath(new URL("./ArgusConnectionContent.tsx", import.meta.url)),
  "utf-8",
)
const apiSrc = readFileSync(
  fileURLToPath(new URL("../../../../lib/client/argus-settings-api.ts", import.meta.url)),
  "utf-8",
)

describe("argus-settings-api", () => {
  it("targets the per-org Argus settings endpoints", () => {
    assert.match(apiSrc, /"\/api\/v1\/settings\/argus"/)
    assert.match(apiSrc, /"\/api\/v1\/settings\/argus\/test", \{ method: "POST" \}/)
    assert.match(apiSrc, /method: "PUT"/)
    assert.match(apiSrc, /method: "DELETE"/)
  })

  it("sends the secret refresh token only on update (never read back)", () => {
    assert.match(apiSrc, /refresh_token: string/)
    assert.match(apiSrc, /interface ArgusConnection \{[\s\S]*?\}/)
    // The read-back ArgusConnection type must not expose refresh_token.
    const connType = apiSrc.match(/export interface ArgusConnection \{[\s\S]*?\n\}/)?.[0] ?? ""
    assert.doesNotMatch(connType, /refresh_token/)
  })
})

describe("ArgusConnectionContent", () => {
  it("configures the OAuth connection fields, not an LLM key", () => {
    for (const field of ["endpoint", "token_endpoint", "client_id", "refresh_token"]) {
      assert.ok(src.includes(field), `should configure ${field}`)
    }
    assert.doesNotMatch(src, /api_key|LLM provider|OpenAI-compatible/)
  })

  it("wires save / test / disconnect to the api client", () => {
    assert.match(src, /updateArgusConnection\(/)
    assert.match(src, /testArgusConnection\(/)
    assert.match(src, /disconnectArgus\(/)
  })

  it("gates editing on the canEdit permission, not a role", () => {
    assert.match(src, /canEdit = true/)
    assert.match(src, /if \(!canEdit && !sessionLoading\)/)
    assert.match(src, /manage_settings/)
  })

  it("masks the stored refresh token and requires it to re-save", () => {
    assert.match(src, /•••••••• \(stored\)/)
    assert.match(src, /form\.refresh_token\.length > 0/)
  })
})
