import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const pageSrc = readFileSync(join(ROOT, "app/(app)/sources/page.tsx"), "utf8")
const clientSrc = readFileSync(join(ROOT, "app/(app)/sources/SourcesIndexClient.tsx"), "utf8")
const shellSrc = readFileSync(join(ROOT, "app/(app)/sources/_components/SourcePageShell.tsx"), "utf8")

describe("/sources index page", () => {
  it("renders a server component that resolves edit permissions", () => {
    assert.ok(pageSrc.includes("requirePermission"))
    assert.ok(pageSrc.includes("SourcesIndexClient"))
  })

  it("seeds initialTab from the ?tab query param (code-repositories default)", () => {
    assert.ok(pageSrc.includes('tab === "container-registry"'))
    assert.ok(pageSrc.includes('"code-repositories"'))
  })
})

describe("SourcesIndexClient", () => {
  it("renders both enabled source tabs (Git Repository and Container Registry)", () => {
    assert.ok(clientSrc.includes('"code-repositories"'))
    assert.ok(clientSrc.includes('"container-registry"'))
    assert.ok(clientSrc.includes("Git Repository"))
    assert.ok(clientSrc.includes("Container Registry"))
  })

  it("does not expose Cloud Infrastructure (kept hidden per Phase 1)", () => {
    assert.ok(!clientSrc.includes("cloud-infrastructure"))
    assert.ok(!clientSrc.includes("Cloud Infrastructure"))
  })

  it("syncs the active tab via URLSearchParams replace", () => {
    assert.ok(clientSrc.includes("router.replace"))
    assert.ok(clientSrc.includes("URLSearchParams"))
  })

  it("delegates content to SourcePageShell with showHeader={false}", () => {
    assert.ok(clientSrc.includes("SourcePageShell"))
    assert.ok(clientSrc.includes("showHeader={false}"))
  })

  it("renders ARIA tablist semantics", () => {
    assert.ok(clientSrc.includes('role="tablist"'))
    assert.ok(clientSrc.includes('role="tab"'))
    assert.ok(clientSrc.includes("aria-selected"))
  })
})

describe("SourcePageShell", () => {
  it("supports a showHeader prop so the index page can render its own chrome", () => {
    assert.ok(shellSrc.includes("showHeader"))
    assert.ok(shellSrc.includes("showHeader = true"))
  })

  it("still renders PageHeader by default for deep-link routes", () => {
    assert.ok(shellSrc.includes("<PageHeader"))
  })
})
