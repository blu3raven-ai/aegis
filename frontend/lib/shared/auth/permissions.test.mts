import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { resolveEffectivePermissions } from "./roles.ts"
import { IMPLIED_PERMISSIONS } from "./permissions.ts"

describe("resolveEffectivePermissions implied grants", () => {
  it("expands manage_settings to imply manage_runners and view_settings", () => {
    // The frontend gate must mirror the backend resolve_role_permissions:
    // anyone with manage_settings already manages runners in practice.
    const effective = resolveEffectivePermissions(["manage_settings"])
    assert.ok(effective.has("manage_runners"), "manage_settings should imply manage_runners")
    assert.ok(effective.has("view_settings"), "manage_settings should imply view_settings")
  })

  it("treats a standalone manage_runners grant as sufficient on its own", () => {
    // Finer-grained delegation: a role granted manage_runners directly (without
    // manage_settings) can still manage runners.
    const effective = resolveEffectivePermissions(["manage_runners"])
    assert.ok(effective.has("manage_runners"))
    assert.ok(!effective.has("manage_settings"), "manage_runners must not back-imply manage_settings")
  })

  it("keeps manage_runners in the manage_settings implication map", () => {
    assert.ok(
      IMPLIED_PERMISSIONS.manage_settings?.includes("manage_runners"),
      "manage_settings must list manage_runners as an implied permission",
    )
  })
})
