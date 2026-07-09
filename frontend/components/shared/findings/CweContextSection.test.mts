import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./CweContextSection.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("CweContextSection", () => {
  it("renders nothing for an uncatalogued CWE", () => {
    assert.match(src, /const info = cweInfo\(cwe\)/)
    assert.match(src, /if \(!info\) return null/)
  })

  it("shows the CWE name and description", () => {
    assert.match(src, /info\.name/)
    assert.match(src, /info\.description/)
  })

  it("shows the MITRE exploit-likelihood badge when rated", () => {
    assert.match(src, /info\.likelihood &&/)
    assert.match(src, /likelihood/)
  })

  it("links the id to MITRE in a new tab with a safe rel", () => {
    assert.match(src, /cwe\.mitre\.org\/data\/definitions/)
    assert.match(src, /target="_blank"/)
    assert.match(src, /rel="noreferrer noopener"/)
  })

  it("uses the standard section heading scale", () => {
    assert.match(src, /text-base font-semibold text-\[var\(--color-text-primary\)\]/)
  })

  it("shows the OWASP Top 10 2021 category for the CWE", () => {
    assert.match(src, /owaspForCwe/)
    assert.match(src, /OWASP Top 10 2021 category/)
  })
})
