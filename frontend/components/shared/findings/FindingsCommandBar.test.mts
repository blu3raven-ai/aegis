import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./FindingsCommandBar.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("FindingsCommandBar (findings-specific wrapper)", () => {
  it("delegates rendering to the shared CommandBar package", () => {
    assert.match(src, /import \{ CommandBar, type AttributeDef, type CustomPickerProps \} from "@\/components\/shared\/command-bar"/)
    assert.match(src, /<CommandBar/)
  })

  it("declares every supported attribute in the static catalogue", () => {
    // Scanner ("tool") moved to the top-level scanner tabs in FindingsBoardView,
    // so it's intentionally absent here.
    for (const key of [
      '"severity"', '"state"', '"assignee"', '"cwe"',
      '"kev"', '"epss"', '"bands"',
    ]) {
      assert.ok(src.includes(`key: ${key}`), `STATIC_ATTRIBUTES must include ${key}`)
    }
  })

  it("offers the SSVC action-band filter as a multi-select enum, not the retired numeric risk_score", () => {
    assert.match(src, /key: "bands"[\s\S]*?type: "enum"/)
    assert.doesNotMatch(src, /key: "risk_score"/)
    // bands is multi-select, so it ships its own picker via customPickers.
    assert.match(src, /customPickers=\{\{ bands: BandMultiPicker \}\}/)
  })

  it("no longer carries a scanner ('tool') control — that lives in the scanner tabs", () => {
    assert.doesNotMatch(src, /key: "tool"/)
    assert.doesNotMatch(src, /onScannerChange/)
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

  it("translates a removed filter (null) back to 'all' for severity, repo, state", () => {
    assert.match(src, /onSeverityChange\(value \?\? "all"\)/)
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
