import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { cweInfo, owaspForCwe } from "./cwe-catalog.ts"

describe("cweInfo", () => {
  it("returns curated context for a known CWE", () => {
    const info = cweInfo("CWE-89")
    assert.equal(info?.name, "SQL Injection")
    assert.equal(info?.likelihood, "High")
    assert.match(info?.description ?? "", /database/i)
  })

  it("is case-insensitive on the prefix", () => {
    assert.equal(cweInfo("cwe-79")?.name, "Cross-site Scripting (XSS)")
  })

  it("returns null for an uncatalogued or malformed id", () => {
    assert.equal(cweInfo("CWE-999999"), null)
    assert.equal(cweInfo("not-a-cwe"), null)
    assert.equal(cweInfo(null), null)
    assert.equal(cweInfo(undefined), null)
    assert.equal(cweInfo(""), null)
  })

  it("omits likelihood for classes MITRE doesn't rate", () => {
    assert.equal(cweInfo("CWE-200")?.likelihood, undefined)
  })

  it("has no empty placeholder entries", () => {
    for (const id of ["CWE-22", "CWE-918", "CWE-798", "CWE-502"]) {
      const info = cweInfo(id)
      assert.ok(info && info.name.length > 0 && info.description.length > 0, `${id} should be populated`)
    }
  })

  it("maps CWEs to their OWASP Top 10 2021 category (authoritative, not the ticket's A06 slip)", () => {
    assert.equal(owaspForCwe("CWE-94"), "A03:2021 Injection")
    assert.equal(owaspForCwe("CWE-502"), "A08:2021 Software and Data Integrity Failures")
    assert.equal(owaspForCwe("CWE-918: SSRF"), "A10:2021 Server-Side Request Forgery")
    assert.equal(owaspForCwe("CWE-99999"), undefined)
    assert.equal(owaspForCwe(undefined), undefined)
  })
})
