import { readFileSync } from "node:fs"
import { describe, it } from "node:test"
import assert from "node:assert/strict"

const src = readFileSync(
  new URL("./RunnerLifecycleActions.tsx", import.meta.url),
  "utf8",
)

describe("RunnerLifecycleActions", () => {
  it("imports all four REST helpers (regression — helpers were declared but unused)", () => {
    // Until PR #793 these were declared in use-runners.ts with zero importers.
    // If a future refactor drops any of them, the runner gets stuck again.
    for (const helper of ["approveRunner", "revokeRunner", "rotateRunnerToken", "deleteRunner"]) {
      assert.match(src, new RegExp(`\\b${helper}\\b`), `missing helper ${helper}`)
    }
  })

  it("renders Approve only when status == pending_approval", () => {
    // The button must be conditional — showing 'Approve' on already-approved
    // runners would confuse the admin and double-fire the endpoint.
    assert.match(src, /isPending\s*=\s*status\s*===\s*"pending_approval"/)
    assert.match(src, /\{isPending\s*&&[\s\S]*?Approve[\s\S]*?\}/)
  })

  it("hides Revoke when already revoked or pending", () => {
    // Revoke is destructive — must not be offered for revoked rows (no-op
    // server-side, confusing to users) or pending rows (approve first).
    assert.match(src, /isRevoked\s*=\s*status\s*===\s*"revoked"/)
    assert.match(src, /\{!isPending\s*&&\s*!isRevoked\s*&&[\s\S]*?Revoke/)
  })

  it("hides Rotate token when revoked (no auth token to rotate)", () => {
    assert.match(src, /\{!isRevoked\s*&&[\s\S]*?Rotate token/)
  })

  it("always offers Delete as the last-resort action", () => {
    // Delete should be available regardless of status — admins need to be
    // able to clear stuck rows out. The destructive variant is unique to
    // Delete so we can anchor on it.
    const deleteBlock = src.match(/<Button\s+variant="destructive"[\s\S]*?<\/Button>/)
    assert.ok(deleteBlock, "destructive Delete button not found")
    assert.doesNotMatch(
      deleteBlock![0],
      /isPending|isRevoked/,
      "Delete is gated on status — should be unconditional",
    )
  })

  it("wraps the three destructive actions in confirmation Dialogs", () => {
    // Revoke / Rotate / Delete each get a Dialog with onConfirm — Approve does
    // not (low-risk, single-click).
    for (const action of ["revoke", "rotate", "delete"]) {
      assert.match(
        src,
        new RegExp(`<Dialog[\\s\\S]*?confirm === "${action}"[\\s\\S]*?onConfirm`, "i"),
        `missing confirmation Dialog for ${action}`,
      )
    }
    // Sanity: there is no confirm === "approve" branch.
    assert.doesNotMatch(src, /confirm === "approve"/)
  })

  it("surfaces the rotated token in a follow-up dialog with copy-to-clipboard", () => {
    // The backend only returns the new token once. If we don't show it the
    // admin can't paste it on the runner host.
    assert.match(src, /rotatedToken/)
    assert.match(src, /navigator\.clipboard\.writeText/)
  })

  it("navigates back to the list after delete (the row is gone)", () => {
    assert.match(src, /useRouter\(\)/)
    assert.match(src, /router\.push\("\/settings\/runners"\)/)
  })

  it("flags Revoke / Rotate / Delete as variant='danger' to match the destructive Button style", () => {
    // Visual cue alignment with the underlying action.
    const dangerCount = (src.match(/variant="danger"/g) ?? []).length
    assert.equal(dangerCount, 3, "expected exactly 3 destructive dialogs (revoke, rotate, delete)")
  })

  it("disables every action button while a request is in flight (prevents double-fire)", () => {
    // Each button reads `busy !== null` to disable while another action is
    // running. Without this you can spam-click approve, racing two POSTs.
    const buttonGuards = src.match(/disabled={busy !== null}/g) ?? []
    assert.ok(buttonGuards.length >= 4, `expected disabled gate on all 4 buttons, got ${buttonGuards.length}`)
  })

  it("surfaces server errors instead of swallowing them silently", () => {
    // A failed approve/revoke without visible feedback leaves the admin
    // wondering why nothing happened.
    assert.match(src, /setError\(/)
    assert.match(src, /\{error\s*&&[\s\S]*?severity-critical/)
  })
})
