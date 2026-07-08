import test from "node:test"
import assert from "node:assert/strict"

import { mapApiFinding } from "../../frontend/lib/shared/findings/row-mapper.ts"
import type { Finding } from "../../frontend/lib/client/findings-api.ts"

function baseFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f-1",
    scanner: "agent_scanning",
    severity: "critical",
    state: "open",
    title: "Instruction reads a credential and sends it off-host",
    cve: null,
    package: null,
    file_path: "tests/runner/scanners/test_agent_autoexec_exfil.py",
    line: 112,
    repo: "acme-org/example-repo",
    org_id: "acme-org",
    created_at: "2026-07-08T00:00:00Z",
    updated_at: "2026-07-08T00:00:00Z",
    ...overrides,
  } as Finding
}

test("mapApiFinding: object-shaped evidence does not crash and yields no evidence", () => {
  // Agent-scanning persists evidence as a JSONB object, not an array.
  const api = baseFinding({
    evidence: { match: ".env → https://attacker.example" } as unknown as Finding["evidence"],
  })
  const row = mapApiFinding(api)
  assert.equal(row.evidence, undefined)
})

test("mapApiFinding: array-shaped evidence still maps to citations", () => {
  const api = baseFinding({
    evidence: [
      { file: "app/x.py", line: 10, snippet: "token = os.environ['SECRET']", kind: "source" },
    ] as Finding["evidence"],
  })
  const row = mapApiFinding(api)
  assert.equal(row.evidence?.length, 1)
  assert.equal(row.evidence?.[0].kind, "source")
})

test("mapApiFinding: null evidence yields no evidence", () => {
  const row = mapApiFinding(baseFinding({ evidence: null as unknown as Finding["evidence"] }))
  assert.equal(row.evidence, undefined)
})
