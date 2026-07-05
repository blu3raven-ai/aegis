import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { describe, it } from "node:test"
import { fileURLToPath } from "node:url"

const src = readFileSync(
  fileURLToPath(new URL("./SecretVerificationSection.tsx", import.meta.url)),
  "utf8",
)

describe("SecretVerificationSection", () => {
  it("renders nothing when the detector couldn't validate", () => {
    assert.match(src, /if \(verified == null\) return null/)
  })

  it("shows a provider-verified live-credential state", () => {
    assert.match(src, /Live credential — provider-verified/)
    assert.match(src, /authenticated this credential against the provider/)
    assert.match(src, /Rotate it immediately/)
  })

  it("shows a not-verified state with rotate guidance", () => {
    assert.match(src, /Not verified live/)
    assert.match(src, /could not confirm this credential is active/)
  })

  it("attributes the check to the scanner in the visible caption", () => {
    assert.match(src, /Checked by the secret scanner/)
  })

  it("uses the standard section heading scale", () => {
    assert.match(src, /text-base font-semibold text-\[var\(--color-text-primary\)\]/)
  })
})

const board = readFileSync(
  fileURLToPath(
    new URL("./FindingsBoardView.tsx", import.meta.url),
  ),
  "utf8",
)

describe("FindingsBoardView secret verification wiring", () => {
  it("renders SecretVerificationSection only for secret findings", () => {
    assert.match(
      board,
      /selectedFinding\.scanner === "secret_scanning" && \(\s*<SecretVerificationSection/,
    )
    assert.match(board, /verified=\{selectedFinding\.secretVerified\}/)
    assert.match(board, /detector=\{selectedFinding\.secretDetector\}/)
  })
})
