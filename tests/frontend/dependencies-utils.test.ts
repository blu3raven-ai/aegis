import test from "node:test"
import assert from "node:assert/strict"
import type { DependenciesFinding } from "@/lib/shared/dependencies/types"
import { filterFindingsSimple, cvssChipClass, formatCvssScore } from "../../frontend/lib/shared/dependencies/utils.ts"

test("formatCvssScore returns dash for missing scores", () => {
  assert.equal(formatCvssScore(null), "-")
  assert.equal(formatCvssScore(undefined), "-")
})

test("formatCvssScore returns dash for zero score", () => {
  assert.equal(formatCvssScore(0), "-")
})

test("formatCvssScore returns one decimal for present scores", () => {
  assert.equal(formatCvssScore(7), "7.0")
  assert.equal(formatCvssScore(7.45), "7.5")
})

test("cvssChipClass returns neutral class for missing score", () => {
  const cls = cvssChipClass(null)
  assert.match(cls, /text-\[var\(--color-text-secondary\)\]/)
  assert.doesNotMatch(cls, /blue|amber|orange|red/)
})

test("cvssChipClass returns neutral class for zero score", () => {
  const cls = cvssChipClass(0)
  assert.match(cls, /text-\[var\(--color-text-secondary\)\]/)
  assert.doesNotMatch(cls, /blue|amber|orange|red/)
})

function makeAlert(overrides: Partial<DependenciesFinding> = {}): DependenciesFinding {
  return {
    number: 1,
    state: "open",
    current_version: "1.0.0",
    dependency: {
      package: { ecosystem: "npm", name: "lodash" },
      manifest_path: "package.json",
      scope: "runtime",
    },
    security_advisory: {
      ghsa_id: "GHSA-1234",
      cve_id: "CVE-2021-1234",
      summary: "Prototype pollution",
      description: "Detailed description",
      severity: "high",
      cvss: { score: 7.4, vector_string: "" },
      published_at: "2021-01-01T00:00:00Z",
      updated_at: "2021-01-01T00:00:00Z",
      references: [],
    },
    security_vulnerability: {
      package: { ecosystem: "npm", name: "lodash" },
      severity: "high",
      vulnerable_version_range: "< 4.17.21",
      first_patched_version: { identifier: "4.17.21" },
    },
    url: "",
    html_url: "https://github.com/org/repo/security/dependabot/1",
    created_at: "2024-01-01T00:00:00Z",
    updated_at: "2024-01-01T00:00:00Z",
    dismissed_at: null,
    dismissed_by: null,
    dismissed_reason: null,
    dismissed_comment: null,
    fixed_at: null,
    repository: {
      id: 1,
      name: "my-repo",
      full_name: "org/my-repo",
      html_url: "https://github.com/org/my-repo",
      private: false,
    },
    ...overrides,
  } as DependenciesFinding
}

test("filterFindingsSimple returns all alerts when no filters set", () => {
  const alerts = [makeAlert(), makeAlert({ state: "fixed" })]
  const result = filterFindingsSimple(alerts, { search: "", state: "", severity: [] })
  assert.equal(result.length, 2)
})

test("filterFindingsSimple filters by state", () => {
  const alerts = [makeAlert({ state: "open" }), makeAlert({ state: "fixed" })]
  const result = filterFindingsSimple(alerts, { search: "", state: "open", severity: [] })
  assert.equal(result.length, 1)
  assert.equal(result[0].state, "open")
})

test("filterFindingsSimple filters by severity", () => {
  const alerts = [makeAlert(), makeAlert({ security_advisory: { ...makeAlert().security_advisory, severity: "critical" } })]
  const result = filterFindingsSimple(alerts, { search: "", state: "", severity: ["critical"] })
  assert.equal(result.length, 1)
  assert.equal(result[0].security_advisory.severity, "critical")
})

test("filterFindingsSimple searches package name case-insensitively", () => {
  const alerts = [makeAlert(), makeAlert({ dependency: { package: { ecosystem: "npm", name: "express" }, manifest_path: "package.json", scope: null } })]
  const result = filterFindingsSimple(alerts, { search: "LODASH", state: "", severity: [] })
  assert.equal(result.length, 1)
  assert.equal(result[0].dependency.package.name, "lodash")
})

test("filterFindingsSimple searches CVE ID", () => {
  const alerts = [makeAlert(), makeAlert({ security_advisory: { ...makeAlert().security_advisory, cve_id: "CVE-2022-9999" } })]
  const result = filterFindingsSimple(alerts, { search: "CVE-2022-9999", state: "", severity: [] })
  assert.equal(result.length, 1)
})

test("filterFindingsSimple searches repo name", () => {
  const alerts = [makeAlert(), makeAlert({ repository: { ...makeAlert().repository, name: "other-service", full_name: "org/other-service" } })]
  const result = filterFindingsSimple(alerts, { search: "other-service", state: "", severity: [] })
  assert.equal(result.length, 1)
})

test("cvssChipClass returns red for score >= 9", () => {
  assert.ok(cvssChipClass(9.0).includes("red"))
  assert.ok(cvssChipClass(10.0).includes("red"))
})

test("cvssChipClass returns orange for score >= 7", () => {
  assert.ok(cvssChipClass(7.0).includes("orange"))
  assert.ok(cvssChipClass(8.9).includes("orange"))
})

test("cvssChipClass returns amber for score >= 4", () => {
  assert.ok(cvssChipClass(4.0).includes("amber"))
})

test("cvssChipClass returns blue for score < 4", () => {
  assert.ok(cvssChipClass(3.9).includes("blue"))
})
