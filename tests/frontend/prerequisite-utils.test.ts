import test from "node:test"
import assert from "node:assert/strict"
import { computeScannerPrereqItems } from "../../frontend/lib/shared/prerequisite-utils.ts"

// `computeScannerPrereqItems` shapes one prerequisite item per scanner based on
// runner connection state and an optional `scanner_status` hint from the API.

test("runner_connected=true with no scanner_status → defaults to ready / pass", () => {
  const result = computeScannerPrereqItems({
    runner_connected: true,
    error: null,
    runner_name: "runner-1",
    runner_platform: "linux/amd64",
  })
  assert.equal(result.canEnable, true)
  assert.equal(result.items.length, 1)
  assert.equal(result.items[0].label, "Scanner")
  assert.equal(result.items[0].status, "pass")
  assert.ok(result.items[0].detail?.includes("runner-1"))
  assert.ok(result.items[0].detail?.includes("linux/amd64"))
})

test("scanner_status=ready with no platform → omits parenthetical", () => {
  const result = computeScannerPrereqItems({
    runner_connected: true,
    error: null,
    scanner_status: "ready",
    runner_name: "runner-2",
  })
  assert.equal(result.items[0].status, "pass")
  assert.equal(result.items[0].detail, "Runner runner-2 connected")
})

test("scanner_status=ready with no runner_name → 'runner' fallback", () => {
  const result = computeScannerPrereqItems({
    runner_connected: true,
    error: null,
    scanner_status: "ready",
  })
  assert.equal(result.items[0].status, "pass")
  assert.ok(result.items[0].detail?.startsWith("Runner runner"))
})

test("runner_connected=false with no scanner_status → defaults to no_runner / fail", () => {
  const result = computeScannerPrereqItems({
    runner_connected: false,
    error: null,
  })
  assert.equal(result.canEnable, false)
  assert.equal(result.items[0].status, "fail")
  assert.ok(result.items[0].detail?.includes("No runner is connected"))
})

test("scanner_status=no_runner explicit → fail with guidance message", () => {
  const result = computeScannerPrereqItems({
    runner_connected: false,
    error: null,
    scanner_status: "no_runner",
  })
  assert.equal(result.items[0].status, "fail")
  assert.ok(result.items[0].detail?.includes("Connect a runner"))
})

test("unknown scanner_status with error → fail, error surfaces as detail", () => {
  const result = computeScannerPrereqItems({
    runner_connected: false,
    error: "scanner heartbeat timeout",
    scanner_status: "degraded",
  })
  assert.equal(result.items[0].status, "fail")
  assert.equal(result.items[0].detail, "scanner heartbeat timeout")
})

test("unknown scanner_status without error → loading state", () => {
  const result = computeScannerPrereqItems({
    runner_connected: false,
    error: null,
    scanner_status: "starting",
  })
  assert.equal(result.items[0].status, "loading")
  assert.ok(result.items[0].detail?.includes("Checking"))
})

test("canEnable always mirrors runner_connected, regardless of scanner_status", () => {
  const ready = computeScannerPrereqItems({
    runner_connected: true,
    error: null,
    scanner_status: "ready",
  })
  const notReady = computeScannerPrereqItems({
    runner_connected: false,
    error: null,
    scanner_status: "ready",
  })
  assert.equal(ready.canEnable, true)
  assert.equal(notReady.canEnable, false)
})
