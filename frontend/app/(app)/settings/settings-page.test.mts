import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const page = readFileSync(new URL("./page.tsx", import.meta.url), "utf8")
const registry = readFileSync(new URL("./registry.tsx", import.meta.url), "utf8")

test("settings page no longer redirects", () => {
  assert.doesNotMatch(page, /redirect\(/)
})

test("settings page renders the settings sections", () => {
  assert.match(page, /SettingsSections/)
})

test("settings page renders a PageHeader", () => {
  assert.match(page, /PageHeader/)
})

test("settings page renders the left section nav", () => {
  assert.match(page, /SettingsInPageNav/)
})

// The registry is the single source of truth for which sections exist; the host
// and breadcrumbs both read it. Hash ids must stay stable — deep links
// (/settings#llm, the Findings "Enable verification" CTA) target them.
const EXPECTED_IDS = [
  "account",
  "notifications",
  "api-keys",
  "general",
  "sso",
  "audit",
  "runners",
  "llm",
  "advisory-data",
  "license",
] as const

for (const id of EXPECTED_IDS) {
  test(`registry defines the "${id}" section`, () => {
    assert.match(registry, new RegExp(`id:\\s*"${id}"`))
  })
}

// LLM verification, Advisory Data, and License are the licensed capability add-ons —
// grouped into a dedicated "add-ons" cluster, distinct from org-admin settings.
for (const id of ["llm", "advisory-data", "license"] as const) {
  test(`registry groups "${id}" under add-ons`, () => {
    const line = registry.split("\n").find((l) => l.includes(`id: "${id}"`))
    assert.ok(line, `no registry line for ${id}`)
    assert.match(line as string, /group:\s*"add-ons"/)
  })
}

// Every section now renders its full detail inline on the card; the old
// summary-card + modal pattern has been removed entirely.
test("every section wires a detailComponent", () => {
  for (const id of EXPECTED_IDS) {
    assert.match(registry, new RegExp(`id: "${id}",[^}]*detailComponent:`))
  }
})

test("the summary/modal pattern is gone", () => {
  assert.doesNotMatch(registry, /summaryComponent:/)
  assert.doesNotMatch(registry, /mode:\s*"modal"/)
  assert.doesNotMatch(registry, /SummaryComponentProps/)
})
