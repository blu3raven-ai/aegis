import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(new URL("./ReportsPageContent.tsx", import.meta.url).pathname, "utf-8")

describe("ReportsPageContent PCI attestation download", () => {
  it("fetches the attestation and checks the response instead of a fire-and-forget anchor", () => {
    assert.match(src, /await fetch\("\/api\/v1\/compliance\/frameworks\/pci-dss\/attestation\.pdf"/)
    assert.match(src, /if \(!res\.ok\)/)
  })

  it("surfaces a message on failure rather than saving the error body as a broken pdf", () => {
    assert.match(src, /setAttestationError\(/)
    assert.match(src, /role="alert"/)
    // A 404 (framework not tracked) gets a distinct, actionable message.
    assert.match(src, /res\.status === 404/)
  })

  it("only downloads on a successful response, via an object URL it revokes", () => {
    assert.match(src, /const blob = await res\.blob\(\)/)
    assert.match(src, /URL\.createObjectURL\(blob\)/)
    assert.match(src, /URL\.revokeObjectURL\(url\)/)
  })

  it("no longer points an anchor straight at the attestation endpoint", () => {
    assert.doesNotMatch(src, /a\.href = "\/api\/v1\/compliance\/frameworks\/pci-dss\/attestation\.pdf"/)
  })
})

describe("ReportsPageContent PCI attestation gating", () => {
  it("resolves whether PCI DSS is a tracked framework", () => {
    assert.match(src, /listFrameworks\(\)/)
    assert.match(src, /f\.id === PCI_DSS_FRAMEWORK/)
    assert.match(src, /const PCI_DSS_FRAMEWORK = "pci-dss"/)
  })

  it("disables the attestation card only once PCI DSS is known to be untracked", () => {
    // Optimistic while unknown/null; disabled only on an explicit false so the
    // card isn't dead during load and the download still fails loudly on a race.
    assert.match(src, /pciTracked === false/)
    assert.match(src, /"pci-attestation": "Track PCI DSS in Compliance to enable"/)
  })
})
