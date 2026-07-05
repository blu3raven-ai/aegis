import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./EmptySourcesState.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("EmptySourcesState", () => {
  it("exports the EmptySourcesState component", () => {
    assert.match(src, /export function EmptySourcesState\s*\(/)
  })

  it("accepts an optional filtered prop typed as boolean", () => {
    assert.match(src, /filtered\?:\s*boolean/)
  })

  it("renders the unfiltered copy", () => {
    assert.ok(src.includes("No sources connected"))
    assert.ok(
      src.includes(
        "Connect a code repository, container registry, or cloud account to start scanning.",
      ),
    )
  })

  it("renders the filtered copy", () => {
    assert.ok(src.includes("No sources match your filters"))
    assert.ok(src.includes("Try clearing the search or adjusting the type filter."))
  })

  it("uses the Database icon from lucide-react", () => {
    assert.match(src, /import\s+\{\s*Database\s*\}\s+from\s+"lucide-react"/)
  })

  it("does not render an Add source CTA (PageHeader owns it)", () => {
    assert.doesNotMatch(src, /Add source/)
    assert.doesNotMatch(src, /<button/)
  })

  it("uses the table-body empty-state layout proportions", () => {
    assert.match(src, /py-20/)
    assert.match(src, /text-center/)
  })
})
