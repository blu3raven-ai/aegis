import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./RuleRow.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("RuleRow status pills", () => {
  it("renders the Active pill", () => {
    assert.ok(src.includes("Active"), "should render Active pill text")
  })

  it("renders the Paused pill", () => {
    assert.ok(src.includes("Paused"), "should render Paused pill text")
  })

  it("renders the violations pill text", () => {
    assert.ok(src.includes("violation"), "should render violations pill text")
  })
})

describe("RuleRow delete confirmation", () => {
  it("confirms with the user before deleting", () => {
    // Regression guard: deletes must be guarded by window.confirm so a
    // misclick cannot silently destroy a rule.
    assert.match(
      src,
      /window\.confirm\(/,
      "should call window.confirm before delete",
    )
  })
})

describe("RuleRow toggle accessibility", () => {
  it("uses role=switch on the toggle", () => {
    assert.ok(
      src.includes('role="switch"'),
      "should expose toggle as a switch role",
    )
  })

  it("wires aria-checked to the enabled state", () => {
    assert.match(
      src,
      /aria-checked=\{rule\.enabled\}/,
      "should reflect enabled state via aria-checked",
    )
  })
})

describe("RuleRow management controls", () => {
  it("gates edit/delete/toggle on canManage", () => {
    // Regression guard: dropping this conditional would expose mutation
    // affordances to users without rule-management permission.
    assert.match(
      src,
      /\{canManage && \(/,
      "should gate management controls behind canManage",
    )
  })
})

describe("RuleRow action summary", () => {
  it("imports summarizeAction from the shared display helper", () => {
    assert.match(
      src,
      /import\s*\{\s*summarizeAction\s*\}\s*from\s*["']@\/lib\/rules-engine\/display["']/,
      "should import summarizeAction from rules-engine/display",
    )
  })

  it("calls summarizeAction on rule.action", () => {
    assert.ok(
      src.includes("summarizeAction(rule.action)"),
      "should render summarised action text",
    )
  })
})

describe("RuleRow view-violations link", () => {
  it("derives the link state from violation_count_open", () => {
    // Regression guard: the link must only render when the rule has
    // open violations. The source aliases rule.violation_count_open to
    // a local before comparing against zero.
    assert.ok(
      src.includes("rule.violation_count_open"),
      "should reference rule.violation_count_open",
    )
    assert.match(
      src,
      /violationsOpen\s*>\s*0/,
      "should gate the link on a > 0 check",
    )
  })
})
