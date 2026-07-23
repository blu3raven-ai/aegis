import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const src = readFileSync(fileURLToPath(new URL("./LlmPanel.tsx", import.meta.url)), "utf-8")
const apiSrc = readFileSync(
  fileURLToPath(new URL("../../../../lib/client/llm-settings-api.ts", import.meta.url)),
  "utf-8",
)

describe("LlmPanel", () => {
  it("wires config / usage / delete to the api client", () => {
    assert.match(src, /getLlmConfig\(/)
    assert.match(src, /updateLlmConfig\(/)
    assert.match(src, /deleteLlmConfig\(/)
  })

  it("saves and discards through the shared page-level save bar", () => {
    assert.match(src, /useSaveBarSection\(/)
    assert.match(src, /id: "llm-verification"/)
    assert.match(src, /onSave: handleSave/)
    assert.match(src, /onDiscard: handleDiscard/)
    // No inline primary Save button — the global save bar owns saving.
    assert.doesNotMatch(src, /variant="primary"/)
  })

  it("keeps discrete actions (test connection, remove) outside the save bar", () => {
    assert.match(src, /TestConnectionButton/)
    assert.match(src, /Remove model/)
  })

  it("tracks a non-secret baseline for dirty detection (api_key is write-only)", () => {
    assert.match(src, /const isDirty =/)
    assert.match(src, /enabled !== baseline\.enabled/)
    // A freshly entered key always counts as a change.
    assert.match(src, /byo\.api_key\.trim\(\)\.length > 0/)
  })

  it("offers the four verification transports, defaulting to auto", () => {
    for (const id of ["auto", "chat", "responses", "anthropic"]) {
      assert.match(apiSrc, new RegExp(`id: "${id}"`))
    }
    assert.match(apiSrc, /Auto \(recommended\)/)
    assert.match(apiSrc, /DEFAULT_LLM_TRANSPORT: LlmTransport = "auto"/)
    // The panel renders every transport option and seeds the form to the default.
    assert.match(src, /LLM_TRANSPORTS\.map/)
    assert.match(src, /transport: DEFAULT_LLM_TRANSPORT/)
  })

  it("sends the transport in the saved payload and shows the anthropic base only for anthropic", () => {
    assert.match(src, /transport: e\.target\.value as LlmTransport/)
    // updateLlmConfig spreads the form (which now carries transport + anthropic_base_url).
    assert.match(src, /updateLlmConfig\(\{ \.\.\.byo, enabled \}\)/)
    assert.match(src, /byo\.transport === "anthropic"/)
    assert.match(src, /anthropic_base_url/)
  })

  it("shows token usage in Insights, not in settings", () => {
    // Usage displays live on the Insights → Usage tab; settings keeps only config.
    assert.doesNotMatch(src, /UsageMeter|CostChart|getLlmUsage/)
    assert.match(src, /\/insights\?tab=usage/)
  })
})
