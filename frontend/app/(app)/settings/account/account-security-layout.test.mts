import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

test("account settings renders row-based security controls", () => {
  const page = readFileSync(new URL("./page.tsx", import.meta.url), "utf8")
  const account = readFileSync(new URL("./AccountContent.tsx", import.meta.url), "utf8")
  const passwordModal = readFileSync(new URL("./PasswordModal.tsx", import.meta.url), "utf8")
  const totpModal = readFileSync(new URL("./TotpSetupModal.tsx", import.meta.url), "utf8")

  assert.match(page, /from\s+"next\/navigation"/)
  assert.match(page, /redirect\("\/settings#profile"\)/)
  assert.match(account, /Two-factor authentication/)
  assert.match(account, /user\.totpEnabled/)
  assert.match(account, /\/api\/v1\/auth\/totp\/disable/)
  assert.match(passwordModal, /New password must be different from your current password\./)
  assert.match(passwordModal, /Save password/)
  assert.match(totpModal, /QR code for authenticator app/)
  assert.match(totpModal, /\/api\/v1\/auth\/totp\/verify/)
})
