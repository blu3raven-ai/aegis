import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./FindingDataflowTrace.tsx", import.meta.url).pathname,
  "utf-8"
)

describe("FindingDataflowTrace", () => {
  it("is a client component (uses useState)", () => {
    assert.match(src, /^"use client"/m, "must declare 'use client' for hooks")
    assert.ok(src.includes("useState"), "should use useState")
  })

  it("exports DataflowStep interface with role union source | intermediate | sink", () => {
    assert.match(src, /export interface DataflowStep\b/, "DataflowStep must be exported")
    assert.ok(src.includes('"source"'), "role union missing 'source'")
    assert.ok(src.includes('"intermediate"'), "role union missing 'intermediate'")
    assert.ok(src.includes('"sink"'), "role union missing 'sink'")
  })

  it("renders nothing when trace is null/undefined/empty", () => {
    assert.match(src, /if\s*\(!trace\s*\|\|\s*trace\.length\s*===\s*0\)\s*return null/,
      "should early-return on missing or empty trace")
  })

  it("supports defaultExpanded prop with default value false", () => {
    assert.match(src, /defaultExpanded\s*=\s*false\b/, "should default defaultExpanded to false")
  })

  it("uses aria-expanded for the toggle button", () => {
    assert.ok(src.includes("aria-expanded"), "toggle needs aria-expanded for screen readers")
  })

  it("renders one li per step with the role label and file:line", () => {
    assert.match(src, /trace\.map\(\(step,\s*i\)/, "should map over trace with step + index")
    assert.ok(src.includes("step.role"), "should render step.role")
    assert.ok(src.includes("step.file") && src.includes("step.line"), "should render step.file and step.line")
    assert.ok(src.includes("step.snippet"), "should render step.snippet inside a <pre>")
  })

  it("uses text-2xs registered utility for badge typography", () => {
    assert.match(src, /text-2xs/, "must use registered text-2xs, not text-[var(--type-2xs)]")
  })

  it("pluralizes 'step' / 'steps' correctly", () => {
    assert.match(src, /trace\.length\s*===\s*1\s*\?\s*""\s*:\s*"s"/,
      "should toggle 's' suffix on count")
  })

  it("exports FindingDataflowTrace as a named export", () => {
    assert.match(src, /export function FindingDataflowTrace\b/, "must be a named export")
  })
})
