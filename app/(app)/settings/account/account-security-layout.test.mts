import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

test("account API exposes two-factor status", () => {
  const meRoute = readFileSync(new URL("../../../api/me/route.ts", import.meta.url), "utf8")
  const client = readFileSync(new URL("../../../../lib/auth/client.ts", import.meta.url), "utf8")

  assert.match(meRoute, /totpEnabled: user\.totpEnabled \?\? false/)
  assert.match(client, /totpEnabled: boolean/)
})

test("TOTP account routes support setup, verify, and disable", () => {
  const setupRoute = readFileSync(new URL("../../../api/settings/account/totp/route.ts", import.meta.url), "utf8")
  const verifyRoute = readFileSync(new URL("../../../api/settings/account/totp/verify/route.ts", import.meta.url), "utf8")
  const pending = readFileSync(new URL("../../../api/settings/account/totp/_pending.ts", import.meta.url), "utf8")

  assert.match(setupRoute, /QRCode\.toDataURL\(uri\)/)
  assert.match(setupRoute, /setPending\(user\.id, secret\)/)
  assert.match(setupRoute, /updateTotpSecret\(user\.id, null, false\)/)
  assert.match(verifyRoute, /getPending\(user\.id\)/)
  assert.match(verifyRoute, /verifyTotpCode\(code, secret\)/)
  assert.match(verifyRoute, /updateTotpSecret\(user\.id, secret, true\)/)
  assert.match(pending, /new Map<string, PendingEntry>\(\)/)
})

test("account settings renders row-based security controls", () => {
  const page = readFileSync(new URL("./page.tsx", import.meta.url), "utf8")
  const account = readFileSync(new URL("./AccountContent.tsx", import.meta.url), "utf8")
  const passwordModal = readFileSync(new URL("./PasswordModal.tsx", import.meta.url), "utf8")
  const totpModal = readFileSync(new URL("./TotpSetupModal.tsx", import.meta.url), "utf8")

  assert.match(page, /<AccountContent \/>/)
  assert.match(account, /Account settings/)
  assert.match(account, /Two-factor authentication/)
  assert.match(account, /user\.totpEnabled/)
  assert.match(account, /fetch\("\/api\/settings\/account\/totp", \{ method: "DELETE" \}\)/)
  assert.match(passwordModal, /New password must be different from your current password\./)
  assert.match(passwordModal, /Save password/)
  assert.match(totpModal, /QR code for authenticator app/)
  assert.match(totpModal, /fetch\("\/api\/settings\/account\/totp\/verify"/)
})

test("settings navigation uses the migrated single-outline account icon", () => {
  const sidebar = readFileSync(new URL("../SidebarNav.tsx", import.meta.url), "utf8")

  assert.match(sidebar, /const ICON_ACCOUNT =\s+"M15\.75 5\.25a3\.75 3\.75 0 1 1-7\.5 0 3\.75 3\.75 0 0 1 7\.5 0ZM4\.501 20\.118a7\.5 7\.5 0 0 1 14\.998 0A17\.933 17\.933 0 0 1 12 21\.75c-2\.676 0-5\.216-\.584-7\.499-1\.632Z"/)
})
