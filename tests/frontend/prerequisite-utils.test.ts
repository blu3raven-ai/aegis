import test from "node:test"
import assert from "node:assert/strict"
import { computeScannerPrereqItems } from "../../lib/shared/prerequisite-utils.ts"

// --- Dependencies scanner ---

test("image present and signed → single pass item, canEnable true", () => {
  const result = computeScannerPrereqItems({
    dockerImagePresent: true, imageName: "dependencies-scanner", signature: "sig123",
    signatureValid: true, digest: "sha256:1234567890", error: null,
    runner_name: "runner-1", runner_platform: "linux/amd64",
  })
  assert.equal(result.canEnable, true)
  assert.equal(result.items.length, 1)
  assert.equal(result.items[0].label, "Scanner image")
  assert.equal(result.items[0].status, "pass")
  assert.ok(result.items[0].detail?.includes("runner-1"))
  assert.ok(result.items[0].detail?.includes("linux/amd64"))
})

test("image missing with error → single fail item, canEnable false", () => {
  const result = computeScannerPrereqItems({
    dockerImagePresent: false, imageName: "dependencies-scanner", signature: null,
    signatureValid: false, digest: null, error: "image not found",
  })
  assert.equal(result.canEnable, false)
  assert.equal(result.items.length, 1)
  assert.equal(result.items[0].status, "fail")
  assert.equal(result.items[0].detail, "image not found")
})

test("no error and not ready → loading status", () => {
  const result = computeScannerPrereqItems({
    dockerImagePresent: false, imageName: "dependencies-scanner", signature: null,
    signatureValid: false, digest: null, error: null,
  })
  assert.equal(result.items[0].status, "loading")
})

test("image present but invalid signature → fail", () => {
  const result = computeScannerPrereqItems({
    dockerImagePresent: true, imageName: "dependencies-scanner", signature: "bad-sig",
    signatureValid: false, digest: "sha256:digest", error: "Invalid signature",
  })
  assert.equal(result.canEnable, false)
  assert.equal(result.items[0].status, "fail")
})

// --- Secrets scanner ---

test("secrets: image present and signed → pass with runner info", () => {
  const result = computeScannerPrereqItems({
    dockerImagePresent: true, imageName: "secret-scanner", signature: "sig123",
    signatureValid: true, digest: "sha256:1234567890", error: null,
    runner_name: "runner-2", runner_platform: "linux/arm64",
  })
  assert.equal(result.canEnable, true)
  assert.ok(result.items[0].detail?.includes("runner-2"))
  assert.ok(result.items[0].detail?.includes("linux/arm64"))
})

test("secrets: runner info falls back gracefully when not provided", () => {
  const result = computeScannerPrereqItems({
    dockerImagePresent: true, imageName: "secret-scanner", signature: "sig123",
    signatureValid: true, digest: "sha256:1234567890", error: null,
  })
  assert.equal(result.items[0].status, "pass")
  assert.ok(result.items[0].detail?.includes("runner"))
})

// --- Scanner status guidance ---

test("scanner_status=building → loading with building message", () => {
  const result = computeScannerPrereqItems({
    dockerImagePresent: false, imageName: "aegis/scanner-dependencies:latest", signature: null,
    signatureValid: false, digest: null, error: "Building on runner",
    scanner_status: "building", runner_name: "local-runner",
  })
  assert.equal(result.items[0].status, "loading")
  assert.ok(result.items[0].detail?.includes("Building"))
})

test("scanner_status=missing → fail with restart command", () => {
  const result = computeScannerPrereqItems({
    dockerImagePresent: false, imageName: "aegis/scanner-dependencies:latest", signature: null,
    signatureValid: false, digest: null, error: "not available",
    scanner_status: "missing", scanner_source: "local", runner_name: "local-runner",
  })
  assert.equal(result.items[0].status, "fail")
  assert.ok(result.items[0].fix?.includes("docker compose restart runner"))
})

test("scanner_status=no_runner → fail with start command", () => {
  const result = computeScannerPrereqItems({
    dockerImagePresent: false, imageName: "", signature: null,
    signatureValid: false, digest: null, error: "No runner",
    scanner_status: "no_runner",
  })
  assert.equal(result.items[0].status, "fail")
  assert.ok(result.items[0].fix?.includes("docker compose up"))
})
