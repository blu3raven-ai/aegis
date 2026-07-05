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
    // Previously secrets always rendered a plain <code> block with no line
    // numbers or highlight; a real redacted window now shows in file context.
    assert.match(src, /const secretShowsWindow = isSecret && !revealed && lines\.length > 1/)
    assert.match(src, /const useCodeLines = !isSecret \|\| secretShowsWindow/)
    assert.match(src, /\{useCodeLines \? \(/)
  })

  it("anchors the gutter and highlight for the secret window", () => {
    assert.match(src, /const anchor = useCodeLines \? startLine \?\? parseStartLine\(filePath\) : null/)
    assert.match(src, /const showGutter = useCodeLines && \(lines\.length > 1 \|\| anchor != null\)/)
    assert.match(src, /highlightStart=\{highlightStart\}/)
  })

  it("blurs the flagged secret line until it is revealed", () => {
    assert.match(src, /const blurHighlighted = isSecret && !revealed/)
    assert.match(src, /blurHighlighted=\{blurHighlighted\}/)
    assert.match(src, /highlighted && blurHighlighted && "select-none blur-\[5px\]"/)
  })
})

describe("CodePreviewSection — reveal permission gate", () => {
  it("gates the Reveal button on the reveal_secret workspace permission", () => {
    // Dedicated, more-sensitive permission the backend enforces on /secret-value;
    // resolved via the workspace (useHasPermission), not a hardcoded role.
    assert.match(src, /useHasPermission\("reveal_secret"\)/)
    assert.match(src, /\{isSecret && canReveal && \(/)
  })

  it("does not promise Reveal in the placeholder when the user can't reveal", () => {
    assert.match(src, /canReveal \? "•+ \(hidden — Reveal to view\)" : "•+ \(hidden\)"/)
  })
})
