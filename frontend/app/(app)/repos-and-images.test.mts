import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "..", "..")

function read(rel: string): string {
  return readFileSync(join(ROOT, rel), "utf8")
}

describe("/repos page", () => {
  it("does not redirect", () => {
    const src = read("app/(app)/repos/page.tsx")
    assert.ok(!src.includes("redirect("), "/repos must not call redirect()")
  })

  it("delegates to the ReposPageClient wrapper", () => {
    const src = read("app/(app)/repos/page.tsx")
    assert.ok(src.includes("ReposPageClient"), "must render ReposPageClient")
  })

  it("ReposPageClient renders RepositoriesPanel with onCountChange", () => {
    const src = read("app/(app)/repos/ReposPageClient.tsx")
    assert.ok(
      src.includes('from "@/app/(app)/sources/_components/RepositoriesPanel"'),
      "must import RepositoriesPanel from its source location",
    )
    assert.match(src, /<RepositoriesPanel\b[^>]*\bonCountChange=\{setCount\}/)
  })

  it("ReposPageClient passes the count into PageHeader inline", () => {
    const src = read("app/(app)/repos/ReposPageClient.tsx")
    assert.ok(src.includes('from "@/components/layout/PageHeader"'))
    assert.ok(src.includes("ReposIcon"))
    assert.match(src, /<PageHeader[\s\S]*?count=\{count\}/)
  })
})

describe("/images page", () => {
  it("is no longer a StubPage", () => {
    const src = read("app/(app)/images/page.tsx")
    assert.ok(!src.includes("StubPage"), "/images must not render StubPage")
  })

  it("delegates to the ImagesPageClient wrapper", () => {
    const src = read("app/(app)/images/page.tsx")
    assert.ok(src.includes("ImagesPageClient"), "must render ImagesPageClient")
  })

  it("ImagesPageClient renders ImagesInventoryPanel with onCountChange", () => {
    const src = read("app/(app)/images/ImagesPageClient.tsx")
    assert.ok(src.includes("ImagesInventoryPanel"), "must render ImagesInventoryPanel")
    assert.match(src, /<ImagesInventoryPanel\b[^>]*\bonCountChange=\{setCount\}/)
  })

  it("ImagesPageClient passes the count into PageHeader inline", () => {
    const src = read("app/(app)/images/ImagesPageClient.tsx")
    assert.ok(src.includes('from "@/components/layout/PageHeader"'))
    assert.ok(src.includes("ImagesIcon"))
    assert.match(src, /<PageHeader[\s\S]*?count=\{count\}/)
  })

  it("inventory panel fetches from the /api/v1/images endpoint", () => {
    const src = read("lib/client/images-api.ts")
    assert.ok(src.includes("/api/v1/images"), "must call /api/v1/images")
    assert.ok(src.includes("export async function listImages"), "must export listImages")
  })

  it("renders an empty state when no images exist", () => {
    const panel = read("app/(app)/images/ImagesInventoryPanel.tsx")
    assert.ok(panel.includes("EmptyImagesState"), "must render EmptyImagesState")
  })
})
