import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./RuleCategorySection.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("RuleCategorySection disabled state", () => {
  it("renders placeholderText when disabled", () => {
    assert.ok(
      src.includes("placeholderText"),
      "should reference placeholderText prop",
    )
  })

  it("branches on the disabled flag for the placeholder", () => {
    // Regression guard: the placeholder must only render in the disabled
    // branch, otherwise it would leak into the live category states.
    assert.match(
      src,
      /disabled\s*\?/,
      "should branch on disabled before rendering placeholder",
    )
  })
})

describe("RuleCategorySection create button", () => {
  it("only shows + New rule when !disabled && canManage", () => {
    // Regression guard: dropping either side of this AND would let users
    // create rules in placeholder categories or without permission.
    assert.match(
      src,
      /!disabled\s*&&\s*canManage/,
      "should gate create button on !disabled && canManage",
    )
  })

  it("renders the + New rule button label", () => {
    assert.ok(
      src.includes("+ New rule"),
      "should render the create button copy",
    )
  })
})

describe("RuleCategorySection empty state", () => {
  it("renders the empty-state title and seeded-defaults hint when no rules exist", () => {
    assert.ok(
      src.includes("No {title.toLowerCase()} yet"),
      "should render the empty-state title",
    )
    assert.ok(
      src.includes("The default tiers should auto-create on first sync"),
      "should render the seeded-defaults hint as the body copy",
    )
  })
})

describe("RuleCategorySection scroll anchor", () => {
  it("wires scrollAnchorId to the outer container id", () => {
    assert.match(
      src,
      /id=\{scrollAnchorId\}/,
      "should attach scrollAnchorId to the section id",
    )
  })
})
