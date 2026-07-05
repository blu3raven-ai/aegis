import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const content = readFileSync(
  join(ROOT, "frontend/app/(app)/releases/ReleasesPageContent.tsx"),
  "utf8",
)
const page = readFileSync(
  join(ROOT, "frontend/app/(app)/releases/page.tsx"),
  "utf8",
)
const client = readFileSync(
  join(ROOT, "frontend/app/(app)/releases/ReleasesPageClient.tsx"),
  "utf8",
)

describe("/releases page wrapper", () => {
  it("delegates to ReleasesPageClient inside a Suspense boundary", () => {
    assert.match(page, /import \{ Suspense \} from "react"/)
    assert.match(page, /<Suspense[^>]*>\s*<ReleasesPageClient\s*\/>\s*<\/Suspense>/)
  })

  it("preserves the metadata export for the title", () => {
    assert.match(page, /export const metadata = \{ title: "Releases" \}/)
  })
})

describe("ReleasesPageClient inline count wiring", () => {
  it("threads the count callback into ReleasesPageContent", () => {
    assert.match(client, /<ReleasesPageContent\s+onCountChange=\{setCount\}\s*\/>/)
  })

  it("passes the count into PageHeader inline", () => {
    assert.match(client, /<PageHeader[\s\S]*?count=\{count\}/)
  })
})

describe("ReleasesPageContent count wiring", () => {
  it("fires onCountChange after a successful list load", () => {
    assert.match(content, /onCountChange\?\.\(data\.releases\.length\)/)
  })
})
