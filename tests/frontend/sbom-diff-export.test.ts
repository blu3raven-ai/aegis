import test from "node:test"
import assert from "node:assert/strict"
import type { SbomDiffResponse } from "../../frontend/lib/client/sbom-diff-api.ts"
import { diffToCsv } from "../../frontend/lib/sbom/diff-export.ts"

function makeDiff(overrides: Partial<SbomDiffResponse> = {}): SbomDiffResponse {
  const added = overrides.added ?? []
  const removed = overrides.removed ?? []
  const version_changed = overrides.version_changed ?? []
  return {
    added,
    removed,
    version_changed,
    unchanged_count: 0,
    remediation_signal_available: true,
    added_count: added.length,
    removed_count: removed.length,
    version_changed_count: version_changed.length,
    truncated: false,
    ...overrides,
  }
}

const HEADER =
  "change,name,ecosystem,from_version,to_version,purl,advisories_known,advisories_resolved,advisories_introduced,advisories_still_vulnerable,open_findings,license_from,license_to"

test("empty diff exports just the header row", () => {
  assert.equal(diffToCsv(makeDiff()), HEADER)
})

test("added / removed / bumped rows map to the right columns", () => {
  const csv = diffToCsv(
    makeDiff({
      added: [
        {
          name: "lodash",
          version: "4.17.21",
          purl: "pkg:npm/lodash@4.17.21",
          type: "npm",
          known_vulns: { critical: 1, high: 0, medium: 0, low: 0, total: 1 },
          current_findings: { critical: 0, high: 2, medium: 0, low: 0, total: 2 },
        },
      ],
      removed: [{ name: "left-pad", version: "1.0.0", type: "npm" }],
      version_changed: [
        {
          name: "react",
          purl: "pkg:npm/react",
          from_version: "18.2.0",
          to_version: "18.3.1",
          resolved: { critical: 0, high: 1, medium: 0, low: 0, total: 1 },
          from_license: "MIT",
          to_license: "MIT",
        },
      ],
    }),
  )
  const lines = csv.split("\r\n")
  assert.equal(lines[0], HEADER)
  // added: ecosystem=npm, from blank, to=version, known=1, open_findings=2
  assert.equal(lines[1], "added,lodash,npm,,4.17.21,pkg:npm/lodash@4.17.21,1,,,,2,,")
  // removed: from=version, to blank, no counts → blanks
  assert.equal(lines[2], "removed,left-pad,npm,1.0.0,,,,,,,,,")
  // version_changed: no ecosystem, from/to versions, resolved=1, licenses
  assert.equal(lines[3], "version_changed,react,,18.2.0,18.3.1,pkg:npm/react,,1,,,,MIT,MIT")
})

test("zero-total counts render as blank, not 0", () => {
  const csv = diffToCsv(
    makeDiff({
      added: [
        {
          name: "safe-pkg",
          version: "1.0.0",
          known_vulns: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
        },
      ],
    }),
  )
  const row = csv.split("\r\n")[1]
  // advisories_known column is blank (index 6), not "0"
  assert.equal(row, "added,safe-pkg,,,1.0.0,,,,,,,,")
})

test("fields with commas or quotes are RFC-4180 quoted", () => {
  const csv = diffToCsv(
    makeDiff({
      version_changed: [
        {
          name: "weird",
          purl: undefined,
          from_version: "1.0.0",
          to_version: "2.0.0",
          from_license: "MIT, with clause",
          to_license: 'GPL "v3"',
        },
      ],
    }),
  )
  const row = csv.split("\r\n")[1]
  assert.ok(row.includes('"MIT, with clause"'))
  assert.ok(row.includes('"GPL ""v3"""'))
})

test("null versions on a bump serialize as empty cells", () => {
  const csv = diffToCsv(
    makeDiff({
      version_changed: [
        { name: "p", purl: undefined, from_version: null, to_version: "2.0.0" },
      ],
    }),
  )
  assert.equal(csv.split("\r\n")[1], "version_changed,p,,,2.0.0,,,,,,,,")
})
