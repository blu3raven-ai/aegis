import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, "..", "..", "..", "..", "..")
const read = (p: string) => readFileSync(join(root, "frontend", p), "utf8")

test("VerificationMetadata carries the advisory fields", () => {
  const src = read("lib/shared/findings/row-mapper.ts")
  for (const field of ["cvss_vector", "cvss_score", "distinctness", "remediation", "poc_filename", "poc_language"]) {
    assert.match(src, new RegExp(`\\b${field}\\??:`), `missing ${field}`)
  }
})

test("findings-api exposes report + poc download URL helpers", () => {
  const src = read("lib/client/findings-api.ts")
  assert.match(src, /report\.md/, "no report.md URL helper")
  assert.match(src, /\/poc/, "no poc URL helper")
})

test("AdvisoryHeader renders the CVSS vector", () => {
  const src = read("components/shared/findings/AdvisoryHeader.tsx")
  assert.match(src, /cvss_vector/, "header must read cvss_vector")
  assert.match(src, /CVSS/, "header must label CVSS")
})

test("drawer wires the advisory sections", () => {
  const src = read("components/shared/findings/FindingsBoardView.tsx")
  assert.match(src, /AdvisoryHeader/, "AdvisoryHeader not mounted")
  assert.match(src, /[Dd]istinctness/, "Distinctness section missing")
  assert.match(src, /[Ss]afe [Hh]arbor/, "Safe Harbor footer missing")
})
