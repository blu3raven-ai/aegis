import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./RecommendedFixSection.tsx", import.meta.url).pathname,
  "utf-8",
)
const mapperSrc = readFileSync(
  new URL("../../../lib/shared/findings/row-mapper.ts", import.meta.url).pathname,
  "utf-8",
)

describe("FindingRecommendedFix type (row-mapper)", () => {
  it("is a discriminated union keyed by kind across all four fix shapes", () => {
    assert.match(
      mapperSrc,
      /kind\?:\s*"upgrade"\s*\|\s*"code_patch"\s*\|\s*"config_patch"\s*\|\s*"rotation"/,
    )
  })

  it("carries shared provenance fields (rationale/confidence/validated/source)", () => {
    assert.match(mapperSrc, /rationale\?:\s*string/)
    assert.match(mapperSrc, /confidence\?:\s*"high"\s*\|\s*"medium"\s*\|\s*"low"/)
    assert.match(mapperSrc, /validated\?:\s*boolean/)
    assert.match(mapperSrc, /source\?:\s*"synthesized"\s*\|\s*"deterministic"\s*\|\s*"llm"/)
  })

  it("keeps the existing upgrade fields", () => {
    assert.match(mapperSrc, /packageName\?:/)
    assert.match(mapperSrc, /fromVersion\?:/)
    assert.match(mapperSrc, /toVersion\?:/)
    assert.match(mapperSrc, /snippet\?:/)
    assert.match(mapperSrc, /diffUrl\?:/)
  })

  it("adds code_patch + config_patch fields (filePath/diff/startLine/endLine/resource/before/after)", () => {
    assert.match(mapperSrc, /filePath\?:/)
    assert.match(mapperSrc, /diff\?:/)
    assert.match(mapperSrc, /startLine\?:/)
    assert.match(mapperSrc, /endLine\?:/)
    assert.match(mapperSrc, /resource\?:/)
    assert.match(mapperSrc, /before\?:/)
    assert.match(mapperSrc, /after\?:/)
  })

  it("adds rotation fields + a typed step shape", () => {
    assert.match(mapperSrc, /export interface FindingRecommendedFixStep/)
    assert.match(mapperSrc, /provider\?:/)
    assert.match(mapperSrc, /verifiedActive\?:/)
    assert.match(mapperSrc, /steps\?:\s*FindingRecommendedFixStep\[\]/)
    for (const field of ["order", "label", "detail", "url", "cli", "destructive"]) {
      assert.ok(mapperSrc.includes(field), `step field missing: ${field}`)
    }
  })
})

describe("RecommendedFixSection", () => {
  it("is a client component returning null with no fix", () => {
    assert.match(src, /^"use client"/m)
    assert.match(src, /if\s*\(!fix\)\s*return null/)
  })

  it("branches on fix.kind across the four kinds", () => {
    assert.match(src, /const kind = fix\.kind/)
    assert.match(src, /kind === "config_patch"/)
    assert.match(src, /kind === "rotation"/)
    assert.match(src, /kind === "code_patch"/)
    assert.match(src, /kind === "upgrade" \|\| kind === undefined/)
  })

  it("never auto-applies a fix", () => {
    assert.doesNotMatch(src, /apply fix/i)
    assert.doesNotMatch(src, /auto-apply/i)
  })

  it("uses the registered text-2xs utility, not text-[var(--type-*)]", () => {
    assert.match(src, /text-2xs/)
    assert.doesNotMatch(src, /text-\[var\(--type-/)
  })
})

describe("RecommendedFixSection — upgrade / undefined (regression-sensitive)", () => {
  it("keeps the 'Upgrade <pkg> from X to Y' vocabulary", () => {
    assert.match(src, /function buildTitle/)
    assert.match(src, /const parts: string\[\] = \["Upgrade"\]/)
    assert.match(src, /from \$\{fix\.fromVersion\} to \$\{fix\.toVersion\}/)
  })

  it("renders the from→to version line with critical/low tinting", () => {
    assert.match(src, /color-severity-critical/)
    assert.match(src, /color-severity-low/)
    assert.match(src, /→/)
  })

  it("offers a copyable snippet with the original CTA + aria-label", () => {
    assert.match(src, /function buildSnippet/)
    assert.match(src, /idleLabel="Copy snippet"/)
    assert.match(src, /ariaLabel="Copy upgrade snippet to clipboard"/)
  })

  it("still wires the optional onViewDiff button", () => {
    assert.match(src, /onClick=\{onViewDiff\}/)
    assert.match(src, /View diff/)
  })
})

describe("RecommendedFixSection — config_patch (IaC)", () => {
  it("renders the resource header and before/after blocks", () => {
    assert.match(src, /function ConfigPatchBody/)
    assert.match(src, /fix\.resource/)
    assert.match(src, /Before/)
    assert.match(src, /After/)
    assert.match(src, /<CodeBlock>\{fix\.before\}<\/CodeBlock>/)
    assert.match(src, /<CodeBlock>\{fix\.after\}<\/CodeBlock>/)
  })

  it("copies the 'after' value and captions the review note", () => {
    assert.match(src, /value=\{fix\.after\}/)
    assert.match(src, /Suggested change — review before applying\./)
  })
})

describe("RecommendedFixSection — rotation (secrets)", () => {
  it("renders an ordered checklist sorted by step order", () => {
    assert.match(src, /function RotationBody/)
    assert.match(src, /\.sort\(\(a, b\) => a\.order - b\.order\)/)
    assert.match(src, /<ol/)
    assert.match(src, /steps\.map\(\(step\)/)
  })

  it("exposes per-step Open console link + Copy CLI button", () => {
    assert.match(src, /Open console/)
    assert.match(src, /idleLabel="Copy CLI"/)
    assert.match(src, /value=\{step\.cli\}/)
  })

  it("marks destructive steps without an action button", () => {
    assert.match(src, /step\.destructive/)
    assert.match(src, /Destructive/)
  })

  it("shows the Verified active badge", () => {
    assert.match(src, /fix\.verifiedActive/)
    assert.match(src, /Verified active/)
  })

  it("keeps the persistent 'deletion is not remediation' caption", () => {
    assert.match(
      src,
      /Removing the secret from code does not remediate it/,
    )
  })
})

describe("RecommendedFixSection — code_patch (SAST)", () => {
  it("renders the diff in a tinted diff block with a file header", () => {
    assert.match(src, /function CodePatchBody/)
    assert.match(src, /function DiffBlock/)
    assert.match(src, /<DiffBlock diff=\{fix\.diff\}/)
    assert.match(src, /fix\.filePath/)
  })

  it("wires onViewDiff and the dormant diffUrl", () => {
    assert.match(src, /onViewDiff \? \(/)
    assert.match(src, /fix\.diffUrl/)
  })
})

describe("RecommendedFixSection — provenance + graceful fallback", () => {
  it("surfaces source/confidence/validated subtly", () => {
    assert.match(src, /function ProvenanceCaption/)
    assert.match(src, /fix\.source/)
    assert.match(src, /fix\.confidence/)
    assert.match(src, /fix\.validated/)
  })

  it("degrades an unknown kind to title/description without crashing", () => {
    assert.match(src, /function GenericBody/)
    assert.match(src, /<GenericBody fix=\{fix\}/)
    assert.match(src, /fix\.title/)
    assert.match(src, /fix\.description/)
  })
})
