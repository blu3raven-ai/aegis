import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(
  new URL("./ScanRunningBanner.tsx", import.meta.url),
  "utf8",
)

test("ScanRunningBanner has a minimize toggle that is not a dismiss", () => {
  // Local state, so minimizing collapses the card without unmounting it — the
  // scan keeps live-updating for its lifetime.
  assert.match(SRC, /const \[minimized, setMinimized\] = useState\(false\)/)
})

test("the full card exposes a Minimize control", () => {
  assert.match(SRC, /aria-label="Minimize scan progress"/)
  assert.match(SRC, /onClick=\{\(\) => setMinimized\(true\)\}/)
})

test("the minimized bar can be restored to the full card", () => {
  assert.match(SRC, /if \(minimized\)/)
  assert.match(SRC, /aria-label="Restore scan progress"/)
  assert.match(SRC, /onClick=\{\(\) => setMinimized\(false\)\}/)
})

test("Cancel scan stays reachable while minimized", () => {
  // The minimized branch keeps the cancel control (onCancel && isActive) so the
  // scan can be stopped without restoring the full card first.
  // The minimized branch runs from `if (minimized)` to the full-card `return (`.
  const start = SRC.indexOf("if (minimized)")
  const minimizedBlock = SRC.slice(start, SRC.indexOf("\n  return (", start))
  assert.match(minimizedBlock, /aria-label="Cancel scan"/)
  assert.match(minimizedBlock, /onCancel && isActive/)
})
