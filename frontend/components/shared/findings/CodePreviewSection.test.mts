import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { describe, it } from "node:test"
import { fileURLToPath } from "node:url"

const src = readFileSync(
  fileURLToPath(new URL("./CodePreviewSection.tsx", import.meta.url)),
  "utf8",
)

describe("CodePreviewSection — secret window", () => {
  it("renders a secret's multi-line window through CodeLines (gutter + highlight)", () => {
    // A real redacted window shows in file context (not a plain <code> block).
    assert.match(src, /const secretShowsWindow = isSecret && lines\.length > 1/)
    assert.match(src, /const useCodeLines = !isSecret \|\| secretShowsWindow/)
    assert.match(src, /\{useCodeLines \? \(/)
  })

  it("anchors the gutter and highlight for the secret window", () => {
    assert.match(src, /const anchor = useCodeLines \? startLine \?\? parseStartLine\(filePath\) : null/)
    assert.match(src, /const showGutter = useCodeLines && \(lines\.length > 1 \|\| anchor != null\)/)
    assert.match(src, /highlightStart=\{highlightStart\}/)
  })

  it("does not blur the flagged secret line (runner masks it to a safe partial)", () => {
    assert.match(src, /const blurHighlighted = false/)
    assert.match(src, /Only a short prefix is shown/)
  })
})

describe("CodePreviewSection — no in-app secret reveal", () => {
  it("offers no reveal control, permission gate, or raw-value fetch", () => {
    // The raw secret is never persisted; the portal must not become a plaintext
    // secret store. So there is no reveal button, no fetch, and no gate here.
    assert.doesNotMatch(src, /revealSecretValue/)
    assert.doesNotMatch(src, /useHasPermission/)
    assert.doesNotMatch(src, /canReveal/)
  })

  it("shows the masked value as redacted, not a broken reveal affordance", () => {
    assert.match(src, /•+ \(redacted\)/)
    assert.match(src, /full secret is never stored/i)
  })
})
