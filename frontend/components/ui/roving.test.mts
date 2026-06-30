import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { handleRovingKeyDown } from "./roving.ts"

type Opts = {
  index: number
  count: number
  orientation?: "horizontal" | "vertical" | "both"
  isDisabled?: (i: number) => boolean
}

function run(key: string, opts: Opts): { moved: number | null; prevented: boolean } {
  let moved: number | null = null
  let prevented = false
  handleRovingKeyDown(
    { key, preventDefault: () => { prevented = true } },
    { ...opts, onMove: (n) => { moved = n } },
  )
  return { moved, prevented }
}

describe("handleRovingKeyDown", () => {
  it("ArrowRight steps forward; wraps at the end", () => {
    assert.equal(run("ArrowRight", { index: 0, count: 3 }).moved, 1)
    assert.equal(run("ArrowRight", { index: 2, count: 3 }).moved, 0)
  })

  it("ArrowLeft steps back; wraps at the start", () => {
    assert.equal(run("ArrowLeft", { index: 2, count: 3 }).moved, 1)
    assert.equal(run("ArrowLeft", { index: 0, count: 3 }).moved, 2)
  })

  it("Home/End jump to first/last", () => {
    assert.equal(run("Home", { index: 2, count: 3 }).moved, 0)
    assert.equal(run("End", { index: 0, count: 3 }).moved, 2)
  })

  it("skips disabled items when stepping", () => {
    assert.equal(run("ArrowRight", { index: 0, count: 3, isDisabled: (i) => i === 1 }).moved, 2)
    assert.equal(run("Home", { index: 2, count: 3, isDisabled: (i) => i === 0 }).moved, 1)
  })

  it("orientation gates which arrows are live", () => {
    assert.equal(run("ArrowRight", { index: 0, count: 3, orientation: "vertical" }).moved, null)
    assert.equal(run("ArrowDown", { index: 0, count: 3, orientation: "vertical" }).moved, 1)
    assert.equal(run("ArrowDown", { index: 0, count: 3, orientation: "both" }).moved, 1)
  })

  it("preventDefault fires only on an actual move", () => {
    assert.equal(run("ArrowRight", { index: 0, count: 3 }).prevented, true)
    assert.equal(run("ArrowRight", { index: 0, count: 1 }).prevented, false) // single item, no-op
    assert.equal(run("x", { index: 0, count: 3 }).prevented, false) // non-navigation key ignored
  })

  it("does not move when no other enabled item exists", () => {
    assert.equal(run("ArrowRight", { index: 0, count: 3, isDisabled: (i) => i !== 0 }).moved, null)
  })
})
