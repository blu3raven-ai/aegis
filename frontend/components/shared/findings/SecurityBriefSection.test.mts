import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./SecurityBriefSection.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("SecurityBriefSection", () => {
  it("returns null when there's no advisory so callers don't guard", () => {
    assert.match(src, /if \(!advisory\) return null/)
  })

  it("renders the advisory summary", () => {
    assert.match(src, /advisory\.summary/)
  })

  it("surfaces CVSS vector, affected range, fixed version, and publish date", () => {
    assert.match(src, /advisory\.cvss_vector/)
    assert.match(src, /advisory\.affected_range/)
    assert.match(src, /advisory\.fixed_version/)
    assert.match(src, /Published/)
  })

  it("does not render when summary, description, facts, and KEV are all absent", () => {
    assert.match(src, /if \(!advisory\.summary && !description && !hasFacts && !kev\) return null/)
  })

  it("renders a CISA KEV callout with due date and ransomware flag", () => {
    assert.match(src, /const kev = advisory\.kev_detail \?\? null/)
    assert.match(src, /CISA Known Exploited/)
    assert.match(src, /Federal agencies must remediate by \$\{kevDue\}/)
    assert.match(src, /kev\.known_ransomware &&/)
    assert.match(src, /Ransomware/)
  })

  it("uses the established 2xs uppercase section heading", () => {
    assert.match(src, /text-2xs font-semibold uppercase tracking-\[0\.14em\]/)
  })

  it("renders the CVSS vector in monospace", () => {
    assert.match(src, /font-mono/)
  })

  it("renders a decoded CVSS breakdown under the vector", () => {
    assert.match(src, /parseCvssVector/)
    assert.match(src, /<CvssBreakdown vector=\{vector\}/)
  })

  it("computes and shows the CVSS base score + severity word", () => {
    assert.match(src, /cvssBaseScore/)
    assert.match(src, /\{scored\.score\.toFixed\(1\)\} \{scored\.severity\}/)
    assert.match(src, /<CvssField vector=\{advisory\.cvss_vector\}/)
  })

  it("offers a Read more expander only when the description adds to the summary", () => {
    assert.match(src, /advisory\.description\.trim\(\) !== \(advisory\.summary \?\? ""\)\.trim\(\)/)
    assert.match(src, /Read full advisory/)
    assert.match(src, /Show less/)
    assert.match(src, /aria-expanded=\{expanded\}/)
  })
})
