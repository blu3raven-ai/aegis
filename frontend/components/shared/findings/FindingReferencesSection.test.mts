import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./FindingReferencesSection.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("FindingReferencesSection", () => {
  it("links CVE ids to NVD", () => {
    assert.match(src, /nvd\.nist\.gov\/vuln\/detail/)
    assert.match(src, /startsWith\("CVE-"\)/)
  })

  it("links GHSA ids to the GitHub advisory database", () => {
    assert.match(src, /github\.com\/advisories/)
    assert.match(src, /startsWith\("GHSA-"\)/)
  })

  it("links CWE ids to MITRE", () => {
    assert.match(src, /cwe\.mitre\.org\/data\/definitions/)
  })

  it("encodes identifiers into the URL rather than interpolating raw", () => {
    assert.match(src, /encodeURIComponent/)
  })

  it("renders nothing when no linkable identifier is present", () => {
    assert.match(src, /if \(refs\.length === 0\) return null/)
  })

  it("opens links in a new tab with a safe rel", () => {
    assert.match(src, /target="_blank"/)
    assert.match(src, /rel="noreferrer noopener"/)
  })

  it("merges the advisory-supplied reference URLs", () => {
    assert.match(src, /advisoryReferences\?: string\[\]/)
    assert.match(src, /for \(const url of advisoryReferences \?\? \[\]\)/)
  })

  it("dedupes advisory URLs against the id-derived links by normalised href", () => {
    assert.match(src, /function normaliseHref/)
    assert.match(src, /if \(seen\.has\(key\)\) continue/)
  })

  it("caps the list so a noisy advisory can't bury the drawer", () => {
    assert.match(src, /MAX_REFERENCES/)
    assert.match(src, /\.slice\(0, MAX_REFERENCES\)/)
  })

  it("only links http(s) reference URLs so a javascript:/data: advisory URL can't XSS", () => {
    // describeUrl's result becomes an <a href>; advisory references are
    // third-party (OSV/GHSA) data and must pass an http(s)-only allowlist.
    assert.match(src, /describeUrl\(url: string\): Reference \| null/)
    assert.match(src, /https\?:\\\/\\\//)
  })

  it("drops a reference that fails the scheme check rather than rendering it as a link", () => {
    assert.match(src, /if \(!ref\) continue/)
  })
})
