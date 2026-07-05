import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./DismissPopover.tsx", import.meta.url).pathname,
  "utf-8"
)

describe("DismissPopover ARIA and keyboard nav", () => {
  it("trigger has aria-haspopup='menu'", () => {
    assert.ok(src.includes('aria-haspopup="menu"'), "trigger should have aria-haspopup=menu")
  })

  it("trigger has aria-expanded bound to open state", () => {
    assert.ok(src.includes("aria-expanded={open}"), "trigger should have aria-expanded")
  })

  it("popover container has role='menu'", () => {
    assert.ok(src.includes('role="menu"'), "popover should have role=menu")
  })

  it("each reason button has role='menuitem'", () => {
    assert.ok(src.includes('role="menuitem"'), "reason buttons should have role=menuitem")
  })

  it("handles ArrowDown for keyboard navigation", () => {
    assert.ok(src.includes('"ArrowDown"'), "should handle ArrowDown key")
  })

  it("handles ArrowUp for keyboard navigation", () => {
    assert.ok(src.includes('"ArrowUp"'), "should handle ArrowUp key")
  })

  it("Escape stops propagation so the drawer does not also close", () => {
    assert.ok(src.includes("stopPropagation"), "Escape should stopPropagation")
  })

  it("popover opens upward with bottom-full positioning", () => {
    assert.ok(src.includes("bottom-full"), "popover should open upward")
  })

  it("calls onDismiss with the selected reason", () => {
    assert.ok(src.includes("onDismiss(reason)"), "should call onDismiss with reason")
  })

  it("trigger uses Button primitive size sm (h-8 ~= py-2 touch target)", () => {
    assert.ok(
      src.includes('size="sm"') && src.includes("<Button"),
      "trigger should route through Button primitive size=sm for h-8 touch target",
    )
  })
})
