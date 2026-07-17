import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const SRC = fileURLToPath(new URL("./AddRunnerModal.tsx", import.meta.url))
const src = readFileSync(SRC, "utf8")

test("modal detects a newly-connected runner via the runner.status SSE event", () => {
  // Snapshots existing runner ids on open so a new one is distinguishable.
  assert.match(src, /knownRunnerIdsRef\.current = new Set/)
  // Subscribes to runner.status and only reacts to an id not seen before.
  assert.match(src, /useSSE\(\s*"runner\.status"/)
  assert.match(src, /knownRunnerIdsRef\.current\.has\(e\.runnerId\)/)
})

test("modal shows a waiting state and a connected confirmation", () => {
  assert.match(src, /Waiting for the runner to connect/)
  assert.ok(
    src.includes("connected") && /\.name\}? (connected|approved)/.test(src),
    "must render the connected/approved runner name",
  )
})

test("modal can approve the connected runner in place", () => {
  assert.match(src, /approveRunner\(connected\.runnerId\)/)
  assert.match(src, /Approve runner/)
})
