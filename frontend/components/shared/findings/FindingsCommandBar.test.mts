import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./FindingsCommandBar.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("FindingsCommandBar (findings-specific wrapper)", () => {
  it("delegates rendering to the shared CommandBar package", () => {
    assert.match(src, /import \{ CommandBar, type AttributeDef \} from "@\/components\/shared\/command-bar"/)
    assert.match(src, /<CommandBar/)
  })

  it("declares every supported attribute in the static catalogue", () => {
    for (const key of [
      '"severity"', '"state"', '"assignee"', '"tool"', '"cwe"',
      '"kev"', '"epss"', '"risk_score"',
    ]) {
      assert.ok(src.includes(`key: ${key}`), `STATIC_ATTRIBUTES must include ${key}`)
    }
  })

  it("flags KEV as a danger-variant boolean attribute", () => {
    assert.match(src, /key: "kev"[\s\S]*?type: "boolean"[\s\S]*?variant: "danger"/)
  })

  it("loads assignees via the existing listAssignableUsers API", () => {
    assert.match(src, /import \{ listAssignableUsers \}/)
    assert.match(src, /asyncLoader:\s*async\s*\(q\)\s*=>/)
  })

  it("formats numeric chips with a ≥ prefix", () => {
    assert.match(src, /displayValue:\s*\(raw\)\s*=>\s*`≥ \$\{raw\}`/)
  })

  it("translates a removed filter (null) back to 'all' for severity, tool, repo, state", () => {
    assert.match(src, /onSeverityChange\(value \?\? "all"\)/)
    assert.match(src, /onScannerChange\(value \?\? "all"\)/)
    assert.match(src, /onRepoChange\(value \?\? "all"\)/)
    assert.match(src, /onStateChange\(value \?\? "all"\)/)
  })

  it("slots FindingsDisplayOverflow as the page-specific overflow", () => {
    assert.match(src, /displayOverflow=\{\s*\n?\s*<FindingsDisplayOverflow/)
  })

  it("does not import @radix-ui (no new dependency)", () => {
    assert.doesNotMatch(src, /@radix-ui/)
  })
})
