import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const src = readFileSync(fileURLToPath(new URL("./AddConnectionModal.tsx", import.meta.url)), "utf-8")

describe("AddConnectionModal", () => {
  it("routes a git-repo connection into the repo picker and saves via finishCreate", () => {
    assert.match(src, /"pick-repos"/)
    assert.match(src, /<RepoPicker/)
    assert.match(src, /finishCreate\("selected", included\)/)
  })

  it("only shows the cherry-pick picker for code-repositories; other categories create directly", () => {
    // Container registries etc. discover images, not repos, so they must not be
    // pushed through the git-repo picker.
    assert.match(src, /category === "code-repositories"/)
    assert.match(src, /finishCreate\("all", \[\]\)/)
  })

  it("shares one finishCreate helper that always sets includedItems on the payload", () => {
    assert.match(src, /async function finishCreate\(/)
    assert.match(src, /includedItems,/)
  })
})
