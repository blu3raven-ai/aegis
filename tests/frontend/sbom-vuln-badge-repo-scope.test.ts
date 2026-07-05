import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

// A vuln badge on a single repo's SBOM must deep-link to that repo's findings,
// not the estate-wide list — otherwise the destination count won't match the
// badge the analyst clicked. These assertions guard the repo scoping wiring.
const ROOT = join(import.meta.dirname, "../..")
const read = (p: string) => readFileSync(join(ROOT, p), "utf8")

const badge = read("frontend/components/shared/sbom/ComponentVulnBadge.tsx")
const table = read("frontend/components/shared/sbom/SbomComponentsTable.tsx")
const repoPage = read("frontend/app/(app)/sbom/[repoId]/SbomRepoPageContent.tsx")

describe("ComponentVulnBadge — repo-scoped findings link", () => {
  it("accepts an optional repo prop", () => {
    assert.match(badge, /repo\?: string/)
  })

  it("appends &repo= only when repo is provided", () => {
    assert.match(
      badge,
      /\(repo \? `&repo=\$\{encodeURIComponent\(repo\)\}` : ""\)/,
    )
  })
})

describe("SbomComponentsTable — threads repo to the badge", () => {
  it("accepts an optional repo prop", () => {
    assert.match(table, /\/\*\* This repo's display_name[^]*?\*\/\s*\n\s*repo\?: string/)
  })

  it("passes repo down to ComponentVulnBadge", () => {
    assert.match(table, /<ComponentVulnBadge[^>]*packageName=\{c\.name\}[^>]*repo=\{repo\}/)
  })
})

describe("SbomRepoPageContent — supplies display_name as the scope key", () => {
  it("captures the raw display_name separately from the header label", () => {
    assert.match(repoPage, /setRepoDisplayName\(r\.display_name \|\| null\)/)
  })

  it("scopes the table only when display_name is known", () => {
    assert.match(repoPage, /repo=\{repoDisplayName \?\? undefined\}/)
  })
})
