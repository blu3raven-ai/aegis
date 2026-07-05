import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../../..")
const createdSrc = readFileSync(join(ROOT, "components/shared/api-keys/CreatedKeyDialog.tsx"), "utf8")
const revokeSrc = readFileSync(join(ROOT, "components/shared/api-keys/RevokeKeyConfirmDialog.tsx"), "utf8")

// These tests pin the design-token contract for the API key dialogs.
// They exist because both files previously referenced undefined tokens
// (--color-yellow, --color-yellow-subtle, --color-red) that resolved to
// nothing at runtime — caught by /impeccable audit, fixed in #137. The
// regressions were silent because the node:test runner doesn't compile
// JSX and never resolves CSS.

describe("CreatedKeyDialog token contract", () => {
  it("warning banner uses the state-pending token family (light amber / dark gold)", () => {
    assert.ok(
      createdSrc.includes("var(--color-state-pending-border)"),
      "warning border must use --color-state-pending-border",
    )
    assert.ok(
      createdSrc.includes("var(--color-state-pending-subtle)"),
      "warning background must use --color-state-pending-subtle",
    )
  })

  it("Done button uses the Button primitive primary variant", () => {
    // After the Button-primitive migration the accent / accent-on tokens are
    // pinned inside Button.tsx (primary variant). The dialog only needs to
    // pick that variant.
    assert.ok(
      createdSrc.includes('variant="primary"') && createdSrc.includes("<Button"),
      "Done button must use Button primitive with variant=primary",
    )
  })

  it("does NOT reference the undefined --color-yellow tokens that previously broke rendering", () => {
    assert.ok(!createdSrc.includes("--color-yellow"), "must not reference --color-yellow (never defined in globals.css)")
    assert.ok(!createdSrc.includes("--color-yellow-subtle"), "must not reference --color-yellow-subtle")
  })

  it("backdrop uses --color-overlay-strong (matches the rest of the app's modal chrome)", () => {
    assert.ok(createdSrc.includes("var(--color-overlay-strong)"))
  })

  it("renders as an accessible modal dialog", () => {
    assert.ok(createdSrc.includes('role="dialog"'))
    assert.ok(createdSrc.includes('aria-modal="true"'))
    assert.ok(createdSrc.includes("aria-labelledby"))
  })
})

describe("RevokeKeyConfirmDialog token contract", () => {
  it("destructive Revoke button uses the Button primitive destructive variant", () => {
    // The severity-critical / on-danger tokens are pinned inside Button.tsx
    // (destructive variant). The dialog only needs to pick that variant.
    assert.ok(
      revokeSrc.includes('variant="destructive"') && revokeSrc.includes("<Button"),
      "destructive Revoke must use Button primitive with variant=destructive",
    )
  })

  it("does NOT reference the undefined --color-red token that previously broke rendering", () => {
    assert.ok(!revokeSrc.includes("var(--color-red)"), "must not reference --color-red (never defined in globals.css)")
  })

  it("Cancel button uses the Button primitive secondary variant (border + secondary text, no fill)", () => {
    assert.ok(
      revokeSrc.includes('variant="secondary"') && revokeSrc.includes("<Button"),
      "Cancel must use Button primitive with variant=secondary",
    )
  })

  it("renders as an accessible modal dialog", () => {
    assert.ok(revokeSrc.includes('role="dialog"'))
    assert.ok(revokeSrc.includes('aria-modal="true"'))
    assert.ok(revokeSrc.includes("aria-labelledby"))
  })
})
