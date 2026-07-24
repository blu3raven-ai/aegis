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
  it("wires config / test / update / delete to the api client", () => {
    assert.match(src, /getLlmConfig\(/)
    assert.match(src, /updateLlmConfig\(/)
    assert.match(src, /testLlmConnection\(/)
    assert.match(src, /deleteLlmConfig\(/)
  })

  it("edits inside a modal via the Sheet primitive with a sticky footer", () => {
    assert.match(src, /import \{ Sheet \}/)
    assert.match(src, /variant="modal"/)
    assert.match(src, /footer=/)
    assert.match(src, /Test & save/)
    assert.match(src, /Cancel/)
  })

  it("toggling on with no config opens the modal and does not enable yet", () => {
    // The enable toggle routes through handleToggle, which opens the editor
    // (does not call setEnabled(true)) when the config isn't ready.
    assert.match(src, /onChange=\{handleToggle\}/)
    assert.match(src, /if \(!isConfigured\) \{\s*openModal\(\)/)
  })

  it("toggling off persists enabled=false without a modal or a test", () => {
    assert.match(src, /if \(!next\) \{/)
    assert.match(src, /persistedPayload\(false\)/)
  })

  it("toggling on when configured tests first and only enables on success", () => {
    assert.match(src, /const result = await testLlmConnection\(\)\s*\n\s*if \(!result\.ok\)/)
    assert.match(src, /persistedPayload\(true\)/)
  })

  it("Test & save updates then tests, keeping the modal open on failure", () => {
    // update is awaited before the test call in the modal handler.
    assert.match(src, /const saved = await updateLlmConfig\(\{ \.\.\.byo, enabled \}\)/)
    assert.match(src, /const result = await testLlmConnection\(\)/)
    // On a failed test the handler surfaces the error and returns early
    // (does not enable, does not close), leaving modalOpen untouched.
    assert.match(src, /if \(!result\.ok\) \{/)
    assert.match(src, /setModalError\(result\.detail \|\| result\.error/)
    // On success it enables and closes.
    assert.match(src, /setEnabled\(true\)/)
    assert.match(src, /setModalOpen\(false\)/)
  })

  it("treats the api key as write-only: empty key keeps the stored secret", () => {
    // First-config requires a fresh key; an already-stored key may be left blank.
    assert.match(src, /keyConfigured \|\| byo\.api_key\.trim\(\)\.length > 0/)
    // Persisted re-saves send an empty api_key so the stored secret is preserved.
    assert.match(src, /api_key: "",/)
    assert.match(src, /leave blank to keep/)
  })

  it("shows a read-only summary with an accessible edit affordance", () => {
    assert.match(src, /aria-label="Edit LLM configuration"/)
    assert.match(src, /Pencil/)
    assert.match(src, /StatusPill/)
    // Empty state when nothing is configured yet.
    assert.match(src, /Not configured - enable to connect your model/)
  })

  it("offers the four verification transports, defaulting to auto", () => {
    for (const id of ["auto", "chat", "responses", "anthropic"]) {
      assert.match(apiSrc, new RegExp(`id: "${id}"`))
    }
    assert.match(apiSrc, /Auto \(recommended\)/)
    assert.match(apiSrc, /DEFAULT_LLM_TRANSPORT: LlmTransport = "auto"/)
    // The modal renders every transport option and seeds the form to the default.
    assert.match(src, /LLM_TRANSPORTS\.map/)
    assert.match(src, /transport: DEFAULT_LLM_TRANSPORT/)
  })

  it("sends the transport in the saved payload and shows the anthropic base only for anthropic", () => {
    assert.match(src, /transport: e\.target\.value as LlmTransport/)
    assert.match(src, /updateLlmConfig\(\{ \.\.\.byo, enabled \}\)/)
    assert.match(src, /byo\.transport === "anthropic"/)
    assert.match(src, /anthropic_base_url/)
  })

  it("shows token usage in Insights, not in settings", () => {
    assert.doesNotMatch(src, /UsageMeter|CostChart|getLlmUsage/)
    assert.match(src, /\/insights\?tab=usage/)
  })

  it("surfaces errors accessibly with role=alert", () => {
    assert.match(src, /role="alert"/)
    assert.match(src, /aria-live=/)
  })
})
