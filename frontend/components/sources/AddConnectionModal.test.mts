import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const src = readFileSync(fileURLToPath(new URL("./AddConnectionModal.tsx", import.meta.url)), "utf-8")

describe("AddConnectionModal", () => {
  it("loads the repo picker inline on the settings screen (token stays editable) and saves via finishCreate", () => {
    // Discovery loads the picker inline via hasDiscovered on the same screen as
    // the token field, rather than swapping to a separate step.
    assert.match(src, /hasDiscovered/)
    assert.match(src, /<RepoPicker/)
    assert.match(src, /finishCreate\("selected", included\)/)
  })

  it("does not use a separate pick-repos screen", () => {
    assert.doesNotMatch(src, /"pick-repos"/)
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
