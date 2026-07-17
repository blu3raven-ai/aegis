import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const SRC = fileURLToPath(
  new URL("../../frontend/components/providers/SSEProvider.tsx", import.meta.url),
)

test("SSE onerror re-establishes the stream instead of giving up permanently", () => {
  const source = readFileSync(SRC, "utf8")
  // The give-up branch must schedule a reconnect (a dropped stream that never
  // reconnects is what forced users to refresh for live progress).
  assert.ok(
    source.includes("reconnectTimerRef.current = setTimeout"),
    "onerror must schedule a reconnect timer",
  )
  assert.ok(
    /setTimeout\(\s*\(\)\s*=>\s*\{[^}]*tryBecomeLeader\(\)/.test(source),
    "the reconnect timer must call tryBecomeLeader to re-open the stream",
  )
  // Capped exponential backoff, not a fixed/no delay.
  assert.ok(
    source.includes("RECONNECT_MAX_MS") && source.includes("** (failCountRef.current"),
    "reconnect must use capped exponential backoff",
  )
  // Hand off so another open tab can take over immediately.
  assert.ok(
    source.includes('postMessage({ type: "leader-down" })'),
    "give-up must broadcast leader-down for tab failover",
  )
})

test("reconnect timer is cleared on unmount", () => {
  const source = readFileSync(SRC, "utf8")
  assert.ok(
    /clearTimeout\(reconnectTimerRef\.current\)/.test(source),
    "the reconnect timer must be cleared on cleanup to avoid a leaked timer",
  )
})
