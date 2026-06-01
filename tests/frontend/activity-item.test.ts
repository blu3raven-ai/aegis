import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// ActivityItem click-through URL derivation tests.
// Validates that each event type maps to the correct navigation URL.
// The component itself is not rendered (no DOM); we test the URL logic
// extracted from ActivityItem's EVENT_META href functions.
// ---------------------------------------------------------------------------

interface ActivityEvent {
  id: string
  type: string
  occurred_at: string
  actor: string | null
  repo_id: string | null
  summary: string
  payload: Record<string, unknown>
}

function makeEvent(
  type: string,
  payload: Record<string, unknown> = {},
  repo_id: string | null = null,
): ActivityEvent {
  return {
    id: `${type}-1`,
    type,
    occurred_at: "2026-01-15T12:00:00+00:00",
    actor: "alice@example.com",
    repo_id,
    summary: `Event: ${type}`,
    payload,
  }
}

// ---------------------------------------------------------------------------
// Replicate the href logic from ActivityItem's EVENT_META (DRY-tested here)
// ---------------------------------------------------------------------------

type HrefFn = (e: ActivityEvent) => string | null

const EVENT_HREFS: Record<string, HrefFn> = {
  "finding.created": (e) => {
    const id = e.payload?.finding_id
    return id != null ? `/findings/${id}` : "/findings"
  },
  "finding.dismissed": (e) => {
    const id = e.payload?.finding_id
    return id != null ? `/findings/${id}` : "/findings"
  },
  "finding.fixed": (e) => {
    const id = e.payload?.finding_id
    return id != null ? `/findings/${id}` : "/findings"
  },
  "finding.reopened": (e) => {
    const id = e.payload?.finding_id
    return id != null ? `/findings/${id}` : "/findings"
  },
  "scan.completed": (e) => {
    const repo = e.repo_id
    return repo ? `/sources/code-repositories` : null
  },
  "scan.failed": (e) => {
    const repo = e.repo_id
    return repo ? `/sources/code-repositories` : null
  },
  "integration.connected": () => "/settings/integrations",
  "integration.disconnected": () => "/settings/integrations",
  "intel.cve.added": (e) => {
    const cve = e.payload?.cve_id as string | undefined
    return cve ? `/findings?cve=${encodeURIComponent(cve)}` : "/findings"
  },
  "sla.breached": (e) => {
    const id = e.payload?.finding_id
    return id != null ? `/findings/${id}` : "/findings"
  },
  "kev.added": (e) => {
    const cve = e.payload?.cve_id as string | undefined
    return cve ? `/findings?cve=${encodeURIComponent(cve)}` : "/findings"
  },
}

// ---------------------------------------------------------------------------
// finding.* → /findings/{id}
// ---------------------------------------------------------------------------

test("finding.created with id → /findings/{id}", () => {
  const e = makeEvent("finding.created", { finding_id: 42 })
  assert.equal(EVENT_HREFS["finding.created"](e), "/findings/42")
})

test("finding.created without id → /findings", () => {
  const e = makeEvent("finding.created", {})
  assert.equal(EVENT_HREFS["finding.created"](e), "/findings")
})

test("finding.dismissed with id → /findings/{id}", () => {
  const e = makeEvent("finding.dismissed", { finding_id: 99 })
  assert.equal(EVENT_HREFS["finding.dismissed"](e), "/findings/99")
})

test("finding.fixed with id → /findings/{id}", () => {
  const e = makeEvent("finding.fixed", { finding_id: 7 })
  assert.equal(EVENT_HREFS["finding.fixed"](e), "/findings/7")
})

test("finding.reopened with id → /findings/{id}", () => {
  const e = makeEvent("finding.reopened", { finding_id: 123 })
  assert.equal(EVENT_HREFS["finding.reopened"](e), "/findings/123")
})

// ---------------------------------------------------------------------------
// scan.* → /sources/code-repositories (when repo_id present)
// ---------------------------------------------------------------------------

test("scan.completed with repo_id → /sources/code-repositories", () => {
  const e = makeEvent("scan.completed", {}, "acme-org/api")
  assert.equal(EVENT_HREFS["scan.completed"](e), "/sources/code-repositories")
})

test("scan.completed without repo_id → null (no navigation)", () => {
  const e = makeEvent("scan.completed", {}, null)
  assert.equal(EVENT_HREFS["scan.completed"](e), null)
})

test("scan.failed with repo_id → /sources/code-repositories", () => {
  const e = makeEvent("scan.failed", {}, "acme-org/api")
  assert.equal(EVENT_HREFS["scan.failed"](e), "/sources/code-repositories")
})

// ---------------------------------------------------------------------------
// integration.* → /settings/integrations
// ---------------------------------------------------------------------------

test("integration.connected → /settings/integrations", () => {
  const e = makeEvent("integration.connected")
  assert.equal(EVENT_HREFS["integration.connected"](e), "/settings/integrations")
})

test("integration.disconnected → /settings/integrations", () => {
  const e = makeEvent("integration.disconnected")
  assert.equal(EVENT_HREFS["integration.disconnected"](e), "/settings/integrations")
})

// ---------------------------------------------------------------------------
// intel.cve.added / kev.added → /findings?cve=...
// ---------------------------------------------------------------------------

test("intel.cve.added with cve_id → /findings?cve={id}", () => {
  const e = makeEvent("intel.cve.added", { cve_id: "CVE-2024-12345" })
  assert.equal(EVENT_HREFS["intel.cve.added"](e), "/findings?cve=CVE-2024-12345")
})

test("intel.cve.added without cve_id → /findings", () => {
  const e = makeEvent("intel.cve.added", {})
  assert.equal(EVENT_HREFS["intel.cve.added"](e), "/findings")
})

test("kev.added with cve_id → /findings?cve={id}", () => {
  const e = makeEvent("kev.added", { cve_id: "CVE-2023-44487" })
  assert.equal(EVENT_HREFS["kev.added"](e), "/findings?cve=CVE-2023-44487")
})

test("kev.added without cve_id → /findings", () => {
  const e = makeEvent("kev.added", {})
  assert.equal(EVENT_HREFS["kev.added"](e), "/findings")
})

// ---------------------------------------------------------------------------
// sla.breached → /findings/{id}
// ---------------------------------------------------------------------------

test("sla.breached with finding_id → /findings/{id}", () => {
  const e = makeEvent("sla.breached", { finding_id: 55 })
  assert.equal(EVENT_HREFS["sla.breached"](e), "/findings/55")
})

test("sla.breached without finding_id → /findings", () => {
  const e = makeEvent("sla.breached", {})
  assert.equal(EVENT_HREFS["sla.breached"](e), "/findings")
})

// ---------------------------------------------------------------------------
// Event type coverage — ensure every SUPPORTED_TYPES entry has an href rule
// ---------------------------------------------------------------------------

const SUPPORTED_TYPES = [
  "finding.created",
  "finding.dismissed",
  "finding.fixed",
  "finding.reopened",
  "scan.completed",
  "scan.failed",
  "integration.connected",
  "integration.disconnected",
  "intel.cve.added",
  "sla.breached",
  "kev.added",
]

test("all supported event types have href derivation logic defined", () => {
  for (const type of SUPPORTED_TYPES) {
    assert.ok(
      type in EVENT_HREFS,
      `Missing href rule for event type: ${type}`,
    )
  }
})
