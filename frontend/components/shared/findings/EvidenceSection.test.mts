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

  it("shows the verification locked preview when it isn't enabled on a verifiable finding", () => {
    assert.match(src, /if \(!verificationEnabled && verifiable\)/)
    assert.match(src, /return <VerificationLockedPreview variant=\{variant\} \/>/)
    assert.match(src, /Enable LLM verification to verify this finding/)
    assert.match(src, /blur-\[3px\]/)
    assert.match(src, /href="\/settings#llm"/)
  })

  it("uses reachability framing for the dependency locked preview", () => {
    assert.match(src, /scanner === "dependencies_scanning" \? "reachability" : "exploit"/)
    assert.match(src, /Enable LLM verification to check reachability/)
    assert.match(src, /vulnerable dependency/)
  })

  it("renders nothing when there's no reasoning and the preview doesn't apply", () => {
    assert.match(src, /if \(!hasReasoning\)/)
    assert.match(src, /return null/)
  })

  it("guards the verdict badge so an unverified finding renders no badge", () => {
    assert.match(src, /verdict && <VerdictBadge/)
  })

  it("uses the 2xs uppercase micro-label style for evidence line labels", () => {
    assert.match(src, /text-2xs font-semibold uppercase tracking-\[0\.14em\]/)
  })

  it("numbers evidence rows and cross-links [Rn] citations in the chain", () => {
    assert.match(src, /renderChainWithRefs\(exploitChain!, refCount\)/)
    assert.match(src, /id=\{evidenceRefId\(i \+ 1\)\}/)
    assert.match(src, /scrollIntoView/)
  })

  it("renders a reproduction (proof-of-concept) block when present", () => {
    assert.match(src, /metadata\?\.reproduction\?\.trim\(\)/)
    assert.match(src, /Proof of concept/)
  })
})
