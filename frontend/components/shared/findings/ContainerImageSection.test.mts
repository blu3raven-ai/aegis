import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./ContainerImageSection.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("ContainerImageSection", () => {
  it("renders nothing when there's no image", () => {
    assert.match(src, /if \(!image\) return null/)
  })

  it("renders the image ref as name:tag", () => {
    assert.match(src, /image\.tag \? `\$\{image\.name\}:\$\{image\.tag\}` : image\.name/)
  })

  it("shows base OS, layer count, and digest", () => {
    assert.match(src, /image\.baseOs/)
    assert.match(src, /image\.layerCount != null/)
    assert.match(src, /image\.digest/)
  })

  it("shows the introducing layer as a 1-based ordinal", () => {
    assert.match(src, /image\.layerDigest/)
    assert.match(src, /Introduced in layer/)
    assert.match(src, /image\.layerIndex \+ 1/)
  })

  it("uses the standard section heading scale", () => {
    assert.match(src, /text-base font-semibold text-\[var\(--color-text-primary\)\]/)
  })
})
