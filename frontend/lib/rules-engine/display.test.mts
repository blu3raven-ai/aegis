import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./display.ts", import.meta.url).pathname,
  "utf-8",
)

describe("summarizeAction — SLA branch", () => {
  it("dispatches on isSlaAction", () => {
    assert.match(src, /if\s*\(\s*isSlaAction\(action\)\s*\)/)
  })

  it("renders the fix-within deadline with day pluralisation", () => {
    assert.ok(src.includes("Fix within ${action.deadline_days} day"))
    assert.match(src, /action\.deadline_days\s*===\s*1\s*\?\s*""\s*:\s*"s"/)
  })

  it("renders the escalate-at clause with first escalation hours", () => {
    assert.ok(src.includes("escalate at ${first.at_hours}h"))
  })

  it("pluralises the channel count label", () => {
    assert.ok(src.includes("1 channel"))
    assert.ok(src.includes("${channelCount} channels"))
  })
})

describe("summarizeAction — require_scanners branch", () => {
  it("dispatches on isRequireScannersAction", () => {
    assert.match(src, /if\s*\(\s*isRequireScannersAction\(action\)\s*\)/)
  })

  it("humanizes required scanners via the shared scannerLabel helper", () => {
    // Previously a local 4-key map that dropped iac/agent/deep_audit and leaked
    // raw keys; now routed through the canonical scannerLabel (all 7 members).
    assert.match(src, /scannerLabel\(s\)/)
    assert.match(src, /import \{ scannerLabel \} from "@\/lib\/shared\/findings\/row-mapper"/)
  })

  it("appends a 'required' suffix to the joined labels", () => {
    assert.ok(src.includes('" required"'))
  })

  it("renders an empty-state copy when no scanners are selected", () => {
    assert.ok(src.includes("no scanners required"))
  })
})

describe("summarizeAction — stale_alert branch", () => {
  it("dispatches on isStaleAlertAction", () => {
    assert.match(src, /if\s*\(\s*isStaleAlertAction\(action\)\s*\)/)
  })

  it("renders the stale threshold copy with day pluralisation", () => {
    assert.ok(src.includes("Alert when scan is older than ${action.stale_after_days} day"))
    assert.match(src, /action\.stale_after_days\s*===\s*1\s*\?\s*""\s*:\s*"s"/)
  })

  it("appends the auto re-scan suffix when auto_retrigger is enabled", () => {
    assert.ok(src.includes("(auto re-scan)"))
    assert.match(src, /action\.auto_retrigger\s*\?/)
  })
})

describe("summarizeAction — archive branch", () => {
  it("dispatches on isArchiveAction", () => {
    assert.match(src, /if\s*\(\s*isArchiveAction\(action\)\s*\)/)
  })

  it("renders the archive copy with day pluralisation", () => {
    assert.ok(src.includes("Archive after ${action.after_days} day"))
    assert.match(
      src,
      /Archive after \$\{action\.after_days\} day\$\{action\.after_days\s*===\s*1\s*\?\s*""\s*:\s*"s"\}/,
      "archive copy should pluralise day → days when after_days !== 1",
    )
  })

  it("appends the keep-retrievable suffix", () => {
    assert.ok(src.includes("· keep retrievable"))
  })
})

describe("summarizeAction — delete branch", () => {
  it("dispatches on isDeleteAction", () => {
    assert.match(src, /if\s*\(\s*isDeleteAction\(action\)\s*\)/)
  })

  it("renders the delete copy with day pluralisation", () => {
    assert.ok(src.includes("Delete after ${action.after_days} day"))
    assert.match(
      src,
      /Delete after \$\{action\.after_days\} day\$\{action\.after_days\s*===\s*1\s*\?\s*""\s*:\s*"s"\}/,
      "delete copy should pluralise day → days when after_days !== 1",
    )
  })

  it("appends the permanent suffix to signal irreversibility", () => {
    assert.ok(src.includes("· permanent"))
  })

  it("imports the archive and delete type guards", () => {
    // Regression guard: missing imports would cause silent fall-through
    // to the em-dash branch even though the action shape is well-formed.
    assert.match(src, /isArchiveAction/)
    assert.match(src, /isDeleteAction/)
  })
})

describe("summarizeAction — fallback", () => {
  it("returns an em-dash for unknown action shapes", () => {
    assert.match(src, /return\s*"—"/)
  })
})
