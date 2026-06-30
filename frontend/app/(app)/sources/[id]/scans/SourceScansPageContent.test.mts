import { readFileSync } from "node:fs"
import { describe, it } from "node:test"
import assert from "node:assert/strict"

const src = readFileSync(
  new URL("./SourceScansPageContent.tsx", import.meta.url),
  "utf8",
)

describe("SourceScansPageContent live-refresh subscriptions", () => {
  it("subscribes to all three terminal scan lifecycle events", () => {
    // The scan-history list must repaint when a run reaches a terminal state
    // elsewhere (another tab, the runner, a teammate). Dropping any of these
    // leaves the table showing a stale 'running' row until manual reload.
    for (const event of ["scan.completed", "scan.failed", "scan.cancelled"]) {
      assert.match(
        src,
        new RegExp(`useSSE\\(\\s*["']${event.replace(".", "\\.")}["']`),
        `missing useSSE subscription for ${event}`,
      )
    }
  })

  it("wires scan.cancelled to the same loader as the other lifecycle events", () => {
    // Regression guard: cancellation is the easiest of the three to forget,
    // and a cancelled run that never clears reads as a stuck scan. Anchor it
    // to load() so a refactor can't silently downgrade it to a no-op.
    assert.match(src, /useSSE\(\s*["']scan\.cancelled["']\s*,\s*\(\)\s*=>\s*void load\(\)\s*\)/)
  })

  it("imports useSSE from the SSE provider", () => {
    assert.match(src, /import\s*\{\s*useSSE\s*\}\s*from\s*["']@\/components\/providers\/SSEProvider["']/)
  })
})
