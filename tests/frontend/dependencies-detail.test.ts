import test from "node:test"
import assert from "node:assert/strict"
import { findingIdentityKey } from "../../lib/shared/dependencies/utils.ts"
import type { DependenciesFinding } from "../../lib/shared/dependencies/types.ts"

function makeAdaptedFinding(ghsaId: string, manifestPath: string): DependenciesFinding {
  return {
    number: 0,
    url: "",
    html_url: "",
    state: "open",
    created_at: "2021-03-05T00:00:00Z",
    updated_at: "2021-03-05T00:00:00Z",
    fixed_at: null,
    dismissed_at: null,
    dismissed_by: null,
    dismissed_reason: null,
    dismissed_comment: null,
    security_advisory: {
      ghsa_id: ghsaId,
      cve_id: null,
      severity: "high",
      summary: "Prototype pollution",
      description: "",
      cvss: { score: 7.2, vector_string: null },
      published_at: "",
      updated_at: "",
      references: [],
    },
    current_version: "4.17.4",
    dependency: {
      package: { name: "lodash", ecosystem: "npm" },
      manifest_path: manifestPath,
      scope: null,
    },
    security_vulnerability: {
      package: { ecosystem: "npm", name: "lodash" },
      severity: "high",
      vulnerable_version_range: "< 4.17.21",
      first_patched_version: { identifier: "4.17.21" },
    },
    repository: { id: 0, name: "my-repo", full_name: "org/my-repo", html_url: "", private: false },
  }
}

test("findingIdentityKey produces correct key format", () => {
  const finding = makeAdaptedFinding("GHSA-p6mc-m468-83gw", "package.json")
  const key = findingIdentityKey(finding)
  assert.equal(key, "my-repo::lodash::npm::GHSA-p6mc-m468-83gw::package.json")
})

test("findingIdentityKey key matches backend DependenciesHooks.compute_identity_key format", () => {
  // Backend format: {repo}::{packageName}::{ecosystem}::{advisory_id}::{manifest_path}
  const finding = makeAdaptedFinding("GHSA-abcd-1234-efgh", "requirements.txt")
  const key = findingIdentityKey(finding)
  const parts = key.split("::")
  assert.equal(parts.length, 5)
  assert.equal(parts[0], "my-repo")
  assert.equal(parts[1], "lodash")
  assert.equal(parts[2], "npm")
  assert.equal(parts[3], "GHSA-abcd-1234-efgh")
  assert.equal(parts[4], "requirements.txt")
})

test("adapted finding has empty description (populated by detail query)", () => {
  // description must be "" — not hardcoded data — so the drawer knows to load detail
  const finding = makeAdaptedFinding("GHSA-p6mc-m468-83gw", "package.json")
  assert.equal(finding.security_advisory.description, "")
})

test("adapted finding has empty references (populated by detail query)", () => {
  const finding = makeAdaptedFinding("GHSA-p6mc-m468-83gw", "package.json")
  assert.deepEqual(finding.security_advisory.references, [])
})
