import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

// fileURLToPath (not .pathname) so the `[id]` brackets in this dir decode back
// to literal characters instead of staying percent-encoded (%5Bid%5D).
const clientSrc = readFileSync(
  fileURLToPath(new URL("./FindingRedirectClient.tsx", import.meta.url)),
  "utf-8",
)
const pageSrc = readFileSync(
  fileURLToPath(new URL("./page.tsx", import.meta.url)),
  "utf-8",
)

describe("finding [id] redirect route", () => {
  it("reads the runtime id with use(params) (static export can't prerender it)", () => {
    assert.match(clientSrc, /const \{ id \} = use\(params\)/)
  })

  it("redirects /findings/<id> to the list with ?finding=<id> to open the drawer", () => {
    assert.match(clientSrc, /router\.replace\(/)
    assert.match(clientSrc, /\/findings\?finding=\$\{encodeURIComponent\(id\)\}/)
  })

  it("falls back to the bare list for the static-export stub id", () => {
    assert.match(clientSrc, /id !== "_"/)
    assert.match(clientSrc, /: "\/findings"/)
  })

  it("ships a generateStaticParams stub so the static export build succeeds", () => {
    assert.match(pageSrc, /export function generateStaticParams/)
    assert.match(pageSrc, /\{ id: "_" \}/)
  })
})
