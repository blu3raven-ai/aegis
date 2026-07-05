/**
 * cweInfo() must resolve curated context regardless of how the scanner
 * formats the CWE label. Scanners commonly emit the fuller
 * "CWE-319: Cleartext Transmission of Sensitive Information" form; an
 * anchored bare-id match silently dropped the weakness explainer for
 * exactly those findings.
 */
import test from "node:test"
import assert from "node:assert/strict"
import { cweInfo } from "../../frontend/lib/shared/findings/cwe-catalog.ts"

test("resolves a bare CWE id", () => {
  const info = cweInfo("CWE-319")
  assert.ok(info, "CWE-319 should be in the catalog")
})

test("resolves the fuller 'CWE-NNN: Name' scanner format", () => {
  const info = cweInfo("CWE-319: Cleartext Transmission of Sensitive Information")
  assert.ok(info, "the labelled form must resolve to the same entry")
  assert.deepEqual(info, cweInfo("CWE-319"))
})

test("resolves a lowercase prefix", () => {
  assert.ok(cweInfo("cwe-79"))
})

test("resolves a plain numeric id", () => {
  assert.deepEqual(cweInfo("79"), cweInfo("CWE-79"))
})

test("returns null for an uncatalogued CWE", () => {
  assert.equal(cweInfo("CWE-99999"), null)
})

test("returns null for empty / nullish input", () => {
  assert.equal(cweInfo(""), null)
  assert.equal(cweInfo(null), null)
  assert.equal(cweInfo(undefined), null)
})
