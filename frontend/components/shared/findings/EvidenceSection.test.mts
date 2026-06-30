import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(new URL("./EvidenceSection.tsx", import.meta.url).pathname, "utf-8")

describe("EvidenceSection", () => {
  it("uses the canonical shared VerdictBadge, not a local duplicate", () => {
    assert.match(src, /from "@\/components\/shared\/findings\/VerdictBadge"/)
  })

  it("imports its evidence/metadata types from the shared row-mapper", () => {
    assert.match(src, /from "@\/lib\/shared\/findings\/row-mapper"/)
    assert.match(src, /VerificationEvidence/)
    assert.match(src, /VerificationMetadata/)
  })

  it("renders the verifier's exploit-chain narrative", () => {
    assert.match(src, /exploitChain/)
  })

  it("renders the upstream mitigation behind a ruled_out verdict", () => {
    assert.match(src, /ruled_out_reason/)
    assert.match(src, /Mitigation found/)
  })

  it("shows the Argus locked preview when Argus isn't enabled on a verifiable finding", () => {
    assert.match(src, /if \(!argusEnabled && verifiable\) return <ArgusLockedPreview \/>/)
    assert.match(src, /Enable Argus to verify this finding/)
    assert.match(src, /blur-\[3px\]/)
    assert.match(src, /href="\/settings#argus"/)
  })

  it("renders nothing when Argus has no reasoning and the preview doesn't apply", () => {
    assert.match(src, /if \(!hasReasoning\)/)
    assert.match(src, /return null/)
  })

  it("guards the verdict badge so an unverified finding renders no badge", () => {
    assert.match(src, /verdict && <VerdictBadge/)
  })

  it("uses the established 2xs uppercase section heading", () => {
    assert.match(src, /text-2xs font-semibold uppercase tracking-\[0\.14em\]/)
  })
})
