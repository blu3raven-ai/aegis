import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const src = readFileSync(
  fileURLToPath(new URL("./ImagesPageClient.tsx", import.meta.url)),
  "utf-8",
)

describe("ImagesPageClient", () => {
  it("uses the canonical AddConnectionModal", () => {
    assert.match(src, /from "@\/components\/sources\/AddConnectionModal"/)
    assert.doesNotMatch(src, /_components\/AddConnectionModal/)
  })

  it("locks the modal to container-registry (no repo picker for image registries)", () => {
    assert.match(src, /lockedCategory="container-registry"/)
  })
})
