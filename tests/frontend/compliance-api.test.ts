import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Minimal fetch mock
// ---------------------------------------------------------------------------

interface FetchCall { url: string }

function makeFetchMock(body: unknown, status = 200) {
  const calls: FetchCall[] = []
  const mock = async (input: RequestInfo | URL): Promise<Response> => {
    calls.push({ url: input.toString() })
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

async function loadModule() {
  return import("../../lib/client/compliance-api.ts")
}

// ---------------------------------------------------------------------------
// listFrameworks
// ---------------------------------------------------------------------------

test("listFrameworks fetches from /api/v1/compliance/frameworks", async () => {
  const body = [{ id: "soc2", label: "SOC 2" }, { id: "iso27001", label: "ISO 27001" }]
  const { mock, calls } = makeFetchMock(body)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listFrameworks } = await loadModule()
  const result = await listFrameworks()

  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/compliance/frameworks")
  assert.equal(result.length, 2)
  assert.equal(result[0].id, "soc2")
  assert.equal(result[1].label, "ISO 27001")
})

test("listFrameworks throws on non-ok response", async () => {
  const { mock } = makeFetchMock({ detail: "forbidden" }, 403)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listFrameworks } = await loadModule()
  await assert.rejects(() => listFrameworks(), /403/)
})

// ---------------------------------------------------------------------------
// listFrameworkControls
// ---------------------------------------------------------------------------

test("listFrameworkControls builds correct URL", async () => {
  const body = [
    { id: 1, framework: "soc2", control_id: "CC6.1", title: "Logical access", description: null, category: "Access" },
  ]
  const { mock, calls } = makeFetchMock(body)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listFrameworkControls } = await loadModule()
  const result = await listFrameworkControls("soc2")

  assert.equal(calls.length, 1)
  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/compliance/frameworks/soc2/controls")
  assert.equal(result.length, 1)
  assert.equal(result[0].control_id, "CC6.1")
})

test("listFrameworkControls encodes framework with special chars", async () => {
  const { mock, calls } = makeFetchMock([])
  globalThis.fetch = mock as unknown as typeof fetch

  const { listFrameworkControls } = await loadModule()
  await listFrameworkControls("pci-dss")

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/compliance/frameworks/pci-dss/controls")
})

test("listFrameworkControls throws on 500", async () => {
  const { mock } = makeFetchMock({}, 500)
  globalThis.fetch = mock as unknown as typeof fetch

  const { listFrameworkControls } = await loadModule()
  await assert.rejects(() => listFrameworkControls("soc2"), /500/)
})

// ---------------------------------------------------------------------------
// getFrameworkSummary
// ---------------------------------------------------------------------------

test("getFrameworkSummary builds URL without org_id when omitted", async () => {
  const body = [
    { control_id: "CC6.1", title: "Logical access", category: null, finding_count: 0, chain_count: 0, highest_severity: null },
  ]
  const { mock, calls } = makeFetchMock(body)
  globalThis.fetch = mock as unknown as typeof fetch

  const { getFrameworkSummary } = await loadModule()
  const result = await getFrameworkSummary("soc2")

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/compliance/frameworks/soc2/summary")
  assert.equal(url.searchParams.has("org_id"), false)
  assert.equal(result.length, 1)
  assert.equal(result[0].finding_count, 0)
})

test("getFrameworkSummary appends org_id when provided", async () => {
  const { mock, calls } = makeFetchMock([])
  globalThis.fetch = mock as unknown as typeof fetch

  const { getFrameworkSummary } = await loadModule()
  await getFrameworkSummary("iso27001", "example-org")

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/compliance/frameworks/iso27001/summary")
  assert.equal(url.searchParams.get("org_id"), "example-org")
})

test("getFrameworkSummary throws on 404", async () => {
  const { mock } = makeFetchMock({ detail: "not found" }, 404)
  globalThis.fetch = mock as unknown as typeof fetch

  const { getFrameworkSummary } = await loadModule()
  await assert.rejects(() => getFrameworkSummary("unknown-fw"), /404/)
})

// ---------------------------------------------------------------------------
// getControlFindings
// ---------------------------------------------------------------------------

test("getControlFindings builds correct URL without org_id", async () => {
  const body = {
    framework: "soc2",
    control_id: "CC6.1",
    findings: [
      { id: 1, title: "CVE-2024-1234", severity: "high", scanner_type: "dependencies", state: "open" },
    ],
  }
  const { mock, calls } = makeFetchMock(body)
  globalThis.fetch = mock as unknown as typeof fetch

  const { getControlFindings } = await loadModule()
  const result = await getControlFindings("soc2", "CC6.1")

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/compliance/controls/soc2/CC6.1/findings")
  assert.equal(result.findings.length, 1)
  assert.equal(result.findings[0].severity, "high")
})

test("getControlFindings appends org_id when provided", async () => {
  const { mock, calls } = makeFetchMock({ framework: "soc2", control_id: "CC6.1", findings: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { getControlFindings } = await loadModule()
  await getControlFindings("soc2", "CC6.1", "example-org")

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.searchParams.get("org_id"), "example-org")
})

test("getControlFindings throws on 500", async () => {
  const { mock } = makeFetchMock({}, 500)
  globalThis.fetch = mock as unknown as typeof fetch

  const { getControlFindings } = await loadModule()
  await assert.rejects(() => getControlFindings("soc2", "CC6.1"), /500/)
})

// ---------------------------------------------------------------------------
// getFindingControls
// ---------------------------------------------------------------------------

test("getFindingControls builds URL from numeric id", async () => {
  const body = {
    finding_id: 42,
    mappings: [
      { framework: "soc2", control_id: "CC6.8", title: "Change management", confidence: 0.9, rationale: null },
    ],
  }
  const { mock, calls } = makeFetchMock(body)
  globalThis.fetch = mock as unknown as typeof fetch

  const { getFindingControls } = await loadModule()
  const result = await getFindingControls(42)

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/compliance/findings/42/controls")
  assert.equal(result.finding_id, 42)
  assert.equal(result.mappings.length, 1)
  assert.equal(result.mappings[0].framework, "soc2")
})

test("getFindingControls accepts string id", async () => {
  const { mock, calls } = makeFetchMock({ finding_id: 7, mappings: [] })
  globalThis.fetch = mock as unknown as typeof fetch

  const { getFindingControls } = await loadModule()
  await getFindingControls("7")

  const url = new URL(calls[0].url, "http://localhost")
  assert.equal(url.pathname, "/api/v1/compliance/findings/7/controls")
})

test("getFindingControls throws on 404", async () => {
  const { mock } = makeFetchMock({ detail: "not found" }, 404)
  globalThis.fetch = mock as unknown as typeof fetch

  const { getFindingControls } = await loadModule()
  await assert.rejects(() => getFindingControls(999), /404/)
})
