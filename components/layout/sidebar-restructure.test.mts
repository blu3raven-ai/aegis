import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const sidebar = readFileSync(join(ROOT, "components/layout/SidebarContent.tsx"), "utf8")
const search = readFileSync(join(ROOT, "components/layout/SearchModal.tsx"), "utf8")
const settingsNav = readFileSync(join(ROOT, "app/(app)/settings/SidebarNav.tsx"), "utf8")

describe("Sidebar — Strategy B 12-item, 3-group structure", () => {
  it("renders the three new groups: Work, Scanners, Library", () => {
    assert.ok(sidebar.includes('label="Work"'), "Work group present")
    assert.ok(sidebar.includes('label="Scanners"'), "Scanners group present")
    assert.ok(sidebar.includes('label="Library"'), "Library group present")
  })

  it("dissolves the prior Overview, Sources, Analytics, Operations groups", () => {
    assert.ok(!sidebar.includes('label="Overview"'))
    assert.ok(!sidebar.includes('label="Sources"'))
    assert.ok(!sidebar.includes('label="Analytics"'))
    assert.ok(!sidebar.includes('label="Operations"'))
  })

  it("removes Insights, Activity, Fleet, Integrations from the main sidebar", () => {
    assert.ok(!sidebar.includes('label: "Insights"'))
    assert.ok(!sidebar.includes('label: "Activity"'))
    assert.ok(!sidebar.includes('label: "Fleet"'))
    assert.ok(!sidebar.includes('label: "Integrations"'))
    assert.ok(!sidebar.includes('href: "/insights"'))
    assert.ok(!sidebar.includes('href: "/activity"'))
    assert.ok(!sidebar.includes('href: "/fleet"'))
    assert.ok(!sidebar.includes('href: "/operations"'))
  })

  it("collapses Git Repository + Container Registry into a single Sources entry under Library", () => {
    assert.ok(!sidebar.includes('href: "/sources/code-repositories"'))
    assert.ok(!sidebar.includes('href: "/sources/container-registry"'))
    assert.ok(sidebar.includes('href: "/sources"'))
  })

  it("moves Compliance into the Library group (no longer under Analytics)", () => {
    // libraryItems block declares Compliance — appear as part of the new structure
    assert.match(sidebar, /libraryItems[\s\S]*?label: "Compliance"/)
  })

  it("activates /sources on the Sources entry for /sources or any /sources/* descendant", () => {
    assert.ok(sidebar.includes('href === "/sources"'))
  })
})

describe("SearchModal — sources entries consolidated", () => {
  it("exposes a single Sources entry pointing to /sources", () => {
    assert.match(search, /href: "\/sources",\s+label: "Sources"/)
  })

  it("no longer lists the per-category Git Repository or Container Registry entries", () => {
    assert.ok(!search.includes('"/sources/code-repositories"'))
    assert.ok(!search.includes('"/sources/container-registry"'))
  })

  it("keeps Cloud Infrastructure hidden", () => {
    assert.ok(!search.includes("Cloud Infrastructure"))
    assert.ok(!search.includes("cloud-infrastructure"))
  })

  it("surfaces Fleet and Integrations via Settings", () => {
    assert.ok(search.includes('"/settings/fleet"'))
    assert.ok(search.includes('"/settings/integrations"'))
  })
})

describe("Settings SidebarNav — Fleet and Integrations as System tabs", () => {
  it("adds Fleet and Integrations to the infra/system nav group", () => {
    assert.ok(settingsNav.includes('href: "/settings/fleet"'))
    assert.ok(settingsNav.includes('href: "/settings/integrations"'))
  })
})
