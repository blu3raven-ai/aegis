import { readFileSync } from "node:fs"
import { describe, it } from "node:test"
import assert from "node:assert/strict"

const src = readFileSync(
  new URL("./RemoteRunnerList.tsx", import.meta.url),
  "utf8",
)

describe("RemoteRunnerList — inline approve", () => {
  it("imports approveRunner so pending rows can be flipped without drilling in", () => {
    // Approving from the detail page works but is a needless click for the
    // common case of 'I just registered a runner, let it work.'
    assert.match(src, /from\s+"@\/lib\/client\/settings\/use-runners"/)
    assert.match(src, /\bapproveRunner\b/)
  })

  it("renders Approve only on pending_approval rows", () => {
    // Other statuses fall through to the chevron — the detail page has
    // Revoke/Rotate/Delete.
    assert.match(
      src,
      /runner\.status === "pending_approval"\s*&&\s*canApprove/,
      "inline Approve must be gated on both status==pending_approval AND canApprove",
    )
  })

  it("declares canApprove on the props interface (permission gate)", () => {
    // A viewer without manage_runners must not see an Approve button on
    // pending rows. The parent (RunnersContent.tsx) passes canApprove={canEdit}
    // — this assertion just pins the prop's existence here.
    assert.match(src, /canApprove: boolean/)
  })

  it("stopPropagation on the Approve click so the row's own click handler doesn't fire", () => {
    // Without stopPropagation the Approve button click would also bubble to
    // the Tr's onClick and navigate to the detail page mid-action.
    assert.match(src, /e\.stopPropagation\(\)/)
  })

  it("re-renders the list after a successful inline approve", () => {
    // onChange propagates back to RunnersContent.loadRunners so the row's
    // status badge updates from 'Pending' to whatever the heartbeat says.
    assert.match(src, /onChange\(\)/)
  })

  it("disables the inline Approve button while in flight (prevents double-fire)", () => {
    // The list polls every few seconds, so a stuck busy state would clear
    // on the next refresh. But within the same render, double-click must
    // not race two POSTs.
    assert.match(src, /isLoading=\{busy\}/)
    assert.match(src, /disabled=\{busy\}/)
  })
})
