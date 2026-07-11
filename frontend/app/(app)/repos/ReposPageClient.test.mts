import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const src = readFileSync(
  fileURLToPath(new URL("./ReposPageClient.tsx", import.meta.url)),
  "utf-8",
)

describe("ReposPageClient", () => {
  it("uses the canonical AddConnectionModal (with the repo cherry-pick flow)", () => {
    assert.match(src, /from "@\/components\/sources\/AddConnectionModal"/)
    assert.doesNotMatch(src, /_components\/AddConnectionModal/)
  })

  it("locks the modal to code-repositories", () => {
    assert.match(src, /lockedCategory="code-repositories"/)
  })
})
