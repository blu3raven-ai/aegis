import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../../..")
const page = readFileSync(join(ROOT, "app/(app)/releases/page.tsx"), "utf8")
const client = readFileSync(join(ROOT, "app/(app)/releases/ReleasesPageClient.tsx"), "utf8")
const content = readFileSync(join(ROOT, "app/(app)/releases/ReleasesPageContent.tsx"), "utf8")
const sidebar = readFileSync(join(ROOT, "components/layout/SidebarContent.tsx"), "utf8")

describe("Releases page — server entry", () => {
  it("uses PageHeader with ReleasesIcon and 'Releases' title", () => {
    assert.match(client, /PageHeader/)
    assert.match(client, /ReleasesIcon/)
    assert.match(client, /title="Releases"/)
  })

  it("inherits the branded document title (no per-page metadata override)", () => {
    assert.doesNotMatch(page, /export const metadata/)
  })

  it("renders the ReleasesPageContent client component", () => {
    assert.match(client, /ReleasesPageContent/)
  })
})

describe("Releases page — list content + filters", () => {
  it("calls listReleases from the releases API client", () => {
    assert.match(content, /from\s+"@\/lib\/client\/releases-api"/)
    assert.match(content, /listReleases\s*\(/)
  })

  it("renders verdict filter chips for GO / WARN / NO-GO", () => {
    for (const label of ["GO", "WARN", "NO-GO"]) {
      assert.ok(content.includes(`label: "${label}"`), `missing verdict filter label: ${label}`)
    }
  })

  it("links each row to the repo scan deeplink", () => {
    assert.ok(
      content.includes("`/sources/${encodeURIComponent(release.repo_id)}?scan_id=${encodeURIComponent(release.scan_id)}`"),
      "row href must point at the repo scan deeplink",
    )
  })

  it("renders an empty state with a CTA to trigger a release scan", () => {
    assert.match(content, /No release scans yet/)
    assert.match(content, /Trigger a release scan/)
    assert.match(content, /href="\/sources"/)
  })

  it("renders a filtered empty state with a clear-filter affordance", () => {
    assert.match(content, /No releases match this filter/)
    assert.match(content, /Clear filter/)
  })
})

describe("Releases page — sidebar wiring", () => {
  it("does not expose /releases in the sidebar (reached via /sources → Pre-release scan)", () => {
    assert.doesNotMatch(sidebar, /href:\s*"\/releases"/)
  })
})
