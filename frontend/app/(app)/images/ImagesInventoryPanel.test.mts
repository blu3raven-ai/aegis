import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./ImagesInventoryPanel.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("ImagesInventoryPanel uses the shared CommandBar", () => {
  it("imports CommandBar and AttributeDef from the shared package", () => {
    assert.match(src, /import \{ CommandBar, type AttributeDef \} from "@\/components\/shared\/command-bar"/)
  })

  it("declares filter + registry attributes in the catalogue", () => {
    assert.match(src, /key:\s*"filter"/)
    assert.match(src, /key:\s*"registry"/)
  })

  it("hides the registry attribute when fewer than two registries are present", () => {
    assert.match(src, /registryOptions\.length > 1/)
  })

  it("translates a removed filter (null) back to 'all'", () => {
    assert.match(src, /setFilter\(\(value \?\? "all"\) as FilterMode\)/)
    assert.match(src, /setRegistryFilter\(value \?\? "all"\)/)
  })

  it("slots ImagesDisplayOverflow as the page-specific overflow", () => {
    assert.match(src, /<ImagesDisplayOverflow/)
  })

  it("no longer renders the legacy inline segmented filter buttons or Sort select", () => {
    assert.doesNotMatch(src, /FILTER_LABELS/)
    assert.doesNotMatch(src, /SORT_LABELS/)
  })
})
