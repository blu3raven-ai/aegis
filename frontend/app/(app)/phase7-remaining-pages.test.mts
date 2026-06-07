import { describe, it } from "node:test"
import assert from "node:assert/strict"

describe("Phase 7 — HomeIcon export", () => {
  it("exports HomeIcon from page-icons", async () => {
    const { readFileSync } = await import("node:fs")
    const content = readFileSync(
      new URL("../../lib/shared/ui/page-icons.tsx", import.meta.url),
      "utf8"
    )
    assert.ok(
      /export\s+(function|const)\s+HomeIcon\b/.test(content),
      "HomeIcon must be exported from lib/shared/ui/page-icons.tsx"
    )
  })

  it("HomeShell imports HomeIcon (no local redefinition)", async () => {
    const { readFileSync } = await import("node:fs")
    const content = readFileSync(
      new URL("./HomeShell.tsx", import.meta.url),
      "utf8"
    )
    assert.ok(content.includes('from "@/lib/shared/ui/page-icons"'), "HomeShell must import from page-icons")
    assert.ok(!content.includes("function HomeIcon"), "HomeShell must not define HomeIcon locally")
  })

  it("HomeShell title is 'Home' not 'Security Portal'", async () => {
    const { readFileSync } = await import("node:fs")
    const content = readFileSync(
      new URL("./HomeShell.tsx", import.meta.url),
      "utf8"
    )
    assert.ok(content.includes('"Home"'), "Title must be Home")
    assert.ok(!content.includes("Security Portal"), "Title must not be Security Portal")
  })
})

describe("Phase 7 — Compliance typography", () => {
  it("compliance page uses correct KPI label tracking", async () => {
    const { readFileSync } = await import("node:fs")
    const content = readFileSync(
      new URL("./compliance/page.tsx", import.meta.url),
      "utf8"
    )
    assert.ok(!content.includes("tracking-wider"), "Must not use tracking-wider in KPI chips")
    assert.ok(content.includes("tracking-[0.22em]"), "Must use tracking-[0.22em]")
  })

  it("compliance page uses tabular-nums for KPI values", async () => {
    const { readFileSync } = await import("node:fs")
    const content = readFileSync(
      new URL("./compliance/page.tsx", import.meta.url),
      "utf8"
    )
    assert.ok(content.includes("tabular-nums"), "KPI values must use tabular-nums")
    assert.ok(!content.includes("text-[22px]"), "Must not use text-[22px]")
  })
})

describe("Phase 7 — Chains filter", () => {
  it("chains page does not use a <select> for type filter", async () => {
    const { readFileSync } = await import("node:fs")
    const content = readFileSync(
      new URL("./chains/page.tsx", import.meta.url),
      "utf8"
    )
    assert.ok(!content.includes("<select"), "Chains must not use <select> for type filter")
  })

  it("chains page does not contain stale back-link to findings", async () => {
    const { readFileSync } = await import("node:fs")
    const content = readFileSync(
      new URL("./chains/page.tsx", import.meta.url),
      "utf8"
    )
    assert.ok(!content.includes("All findings"), "Stale back-link must be removed")
  })
})

describe("Phase 7 — Repo detail PageHeader", () => {
  it("RepoDetailPageContent imports PageHeader", async () => {
    const { readFileSync } = await import("node:fs")
    const content = readFileSync(
      new URL("./repos/[repoId]/RepoDetailPageContent.tsx", import.meta.url),
      "utf8"
    )
    assert.ok(content.includes("PageHeader"), "RepoDetailPageContent must use PageHeader")
    assert.ok(content.includes("ReposIcon"), "RepoDetailPageContent must use ReposIcon")
  })

  it("RepoDetailPageContent uses PageHeader instead of inline breadcrumb nav", async () => {
    const { readFileSync } = await import("node:fs")
    const content = readFileSync(
      new URL("./repos/[repoId]/RepoDetailPageContent.tsx", import.meta.url),
      "utf8"
    )
    assert.ok(
      !/<nav\b[^>]*aria-label=["']Breadcrumb["']/i.test(content),
      "Inline breadcrumb nav must be removed (PageHeader provides breadcrumbs)"
    )
  })
})
