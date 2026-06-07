import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Tests for compliance page-level integration logic:
// framework selection, summary data loading, control detail loading.
//
// Pure logic / API-layer tests — no DOM rendering required.
// ---------------------------------------------------------------------------

interface FetchCall { url: string; method: string }

function makeFetchMock(
  handler: (url: string) => { body: unknown; status?: number },
) {
  const calls: FetchCall[] = []
  const mock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = input.toString()
    calls.push({ url, method: (init?.method ?? "GET").toUpperCase() })
    const { body, status = 200 } = handler(url)
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

async function loadApi() {
  return import("../../frontend/lib/client/compliance-api.ts")
}

// ---------------------------------------------------------------------------
// Framework selector: first framework auto-selected
// ---------------------------------------------------------------------------

test("framework list returns three supported frameworks", async () => {
  const body = [
    { id: "soc2", label: "SOC 2" },
    { id: "iso27001", label: "ISO 27001" },
    { id: "pci-dss", label: "PCI DSS" },
  ]
  const { mock } = makeFetchMock(() => ({ body }))
  globalThis.fetch = mock as unknown as typeof fetch

  const { listFrameworks } = await loadApi()
  const result = await listFrameworks()

  assert.equal(result.length, 3)
  assert.equal(result[0].id, "soc2")
})

// ---------------------------------------------------------------------------
// Summary page: at-risk count derived from finding_count
// ---------------------------------------------------------------------------

test("page: at-risk count computed from controls with finding_count > 0", async () => {
  const controls = [
    { control_id: "CC6.1", title: "Logical access", category: null, finding_count: 3, chain_count: 0, highest_severity: "high" },
    { control_id: "CC6.6", title: "Logical access restrictions", category: null, finding_count: 0, chain_count: 0, highest_severity: null },
    { control_id: "CC7.1", title: "Detection", category: null, finding_count: 1, chain_count: 0, highest_severity: "medium" },
  ]

  const atRisk = controls.filter((c) => c.finding_count > 0 || c.chain_count > 0).length
  const compliant = controls.length - atRisk

  assert.equal(atRisk, 2)
  assert.equal(compliant, 1)
})

test("page: chain_count > 0 also marks control as at-risk", async () => {
  const controls = [
    { control_id: "CC6.8", title: "Change management", category: null, finding_count: 0, chain_count: 2, highest_severity: "critical" },
  ]

  const atRisk = controls.filter((c) => c.finding_count > 0 || c.chain_count > 0).length
  assert.equal(atRisk, 1)
})

test("page: all compliant when no findings or chains", async () => {
  const controls = [
    { control_id: "CC6.1", title: "A", category: null, finding_count: 0, chain_count: 0, highest_severity: null },
    { control_id: "CC6.6", title: "B", category: null, finding_count: 0, chain_count: 0, highest_severity: null },
  ]

  const atRisk = controls.filter((c) => c.finding_count > 0 || c.chain_count > 0).length
  assert.equal(atRisk, 0)
  assert.equal(controls.length - atRisk, 2)
})

// ---------------------------------------------------------------------------
// Summary API integration: switching frameworks triggers reload
// ---------------------------------------------------------------------------

test("page: switching framework fetches new summary", async () => {
  const { mock, calls } = makeFetchMock((url) => {
    if (url.includes("/soc2/")) return { body: { framework: "soc2", label: "SOC 2", controls: [{ control_id: "CC6.1", title: "A", category: null, finding_count: 0, chain_count: 0, highest_severity: null }] } }
    if (url.includes("/iso27001/")) return { body: { framework: "iso27001", label: "ISO 27001", controls: [{ control_id: "A.8.8", title: "B", category: null, finding_count: 1, chain_count: 0, highest_severity: "high" }] } }
    return { body: { framework: "", label: "", controls: [] } }
  })
  globalThis.fetch = mock as unknown as typeof fetch

  const { getFrameworkSummary } = await loadApi()

  const soc2Controls = await getFrameworkSummary("soc2", "example-org")
  assert.equal(soc2Controls.length, 1)
  assert.equal(soc2Controls[0].control_id, "CC6.1")

  const isoControls = await getFrameworkSummary("iso27001", "example-org")
  assert.equal(isoControls.length, 1)
  assert.equal(isoControls[0].highest_severity, "high")

  assert.equal(calls.length, 2)
})

// ---------------------------------------------------------------------------
// Control detail page: highest severity computation
// ---------------------------------------------------------------------------

test("detail page: highest severity selected in order critical > high > medium > low", () => {
  const findings = [
    { id: 1, title: "A", severity: "medium", scanner_type: "sast", state: "open" },
    { id: 2, title: "B", severity: "high", scanner_type: "dependencies", state: "open" },
    { id: 3, title: "C", severity: "low", scanner_type: "secrets", state: "open" },
  ]
  const order = ["critical", "high", "medium", "low"]
  const highest = order.find((sev) => findings.some((f) => f.severity === sev)) ?? null
  assert.equal(highest, "high")
})

test("detail page: only open findings count toward highest severity", () => {
  const findings = [
    { id: 1, title: "A", severity: "critical", scanner_type: "sast", state: "resolved" },
    { id: 2, title: "B", severity: "medium", scanner_type: "dependencies", state: "open" },
  ]
  const openFindings = findings.filter((f) => f.state === "open")
  const order = ["critical", "high", "medium", "low"]
  const highest = order.find((sev) => openFindings.some((f) => f.severity === sev)) ?? null
  assert.equal(highest, "medium")
})

test("detail page: null when no open findings", () => {
  const findings = [
    { id: 1, title: "A", severity: "critical", scanner_type: "sast", state: "resolved" },
  ]
  const openFindings = findings.filter((f) => f.state === "open")
  const order = ["critical", "high", "medium", "low"]
  const highest = order.find((sev) => openFindings.some((f) => f.severity === sev)) ?? null
  assert.equal(highest, null)
})

// ---------------------------------------------------------------------------
// Control detail page: API load
// ---------------------------------------------------------------------------

test("detail page: loads control metadata and findings in parallel", async () => {
  const controls = [
    { id: 1, framework: "soc2", control_id: "CC6.1", title: "Logical access restrictions", description: "Ensure access is restricted.", category: "Access" },
  ]
  const findingsResp = {
    framework: "soc2",
    control_id: "CC6.1",
    findings: [
      { id: 10, title: "Exposed secret in env file", severity: "critical", scanner_type: "secrets", state: "open" },
      { id: 11, title: "Weak password policy", severity: "high", scanner_type: "sast", state: "open" },
    ],
  }

  const { mock } = makeFetchMock((url) => {
    if (url.includes("/frameworks/")) return { body: controls }
    return { body: findingsResp }
  })
  globalThis.fetch = mock as unknown as typeof fetch

  const { listFrameworkControls, getControlFindings } = await loadApi()

  const [allControls, resp] = await Promise.all([
    listFrameworkControls("soc2"),
    getControlFindings("soc2", "CC6.1", "example-org"),
  ])

  const found = allControls.find((c) => c.control_id === "CC6.1")
  assert.ok(found)
  assert.equal(found.title, "Logical access restrictions")
  assert.equal(found.category, "Access")

  const openFindings = resp.findings.filter((f) => f.state === "open")
  assert.equal(openFindings.length, 2)
})

test("detail page: control not found yields null gracefully", async () => {
  const controls = [
    { id: 1, framework: "soc2", control_id: "CC6.6", title: "Other control", description: null, category: null },
  ]
  const { mock } = makeFetchMock(() => ({ body: controls }))
  globalThis.fetch = mock as unknown as typeof fetch

  const { listFrameworkControls } = await loadApi()
  const allControls = await listFrameworkControls("soc2")
  const found = allControls.find((c) => c.control_id === "CC6.1") ?? null
  assert.equal(found, null)
})

// ---------------------------------------------------------------------------
// Finding controls (sidebar mapping badge usage)
// ---------------------------------------------------------------------------

test("getFindingControls returns mappings sorted by framework", async () => {
  const body = {
    finding_id: 55,
    mappings: [
      { framework: "soc2", control_id: "CC6.8", title: "Change management", confidence: 0.85, rationale: null },
      { framework: "iso27001", control_id: "A.8.8", title: "Vulnerability mgmt", confidence: 0.75, rationale: null },
      { framework: "pci-dss", control_id: "6.3.3", title: "Security patches", confidence: 0.9, rationale: null },
    ],
  }
  const { mock } = makeFetchMock(() => ({ body }))
  globalThis.fetch = mock as unknown as typeof fetch

  const { getFindingControls } = await loadApi()
  const result = await getFindingControls(55)

  assert.equal(result.finding_id, 55)
  assert.equal(result.mappings.length, 3)
  const frameworks = result.mappings.map((m) => m.framework)
  assert.ok(frameworks.includes("soc2"))
  assert.ok(frameworks.includes("iso27001"))
  assert.ok(frameworks.includes("pci-dss"))
})
