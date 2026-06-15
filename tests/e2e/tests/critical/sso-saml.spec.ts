import { expect, test } from "@playwright/test"
import { startTestIdp, type TestIdp } from "../../fixtures/saml-idp"

let idp: TestIdp | null = null

test.beforeAll(async () => {
  idp = await startTestIdp()
  if (idp === null) {
    test.skip(true, "Docker is not available; skipping SAML e2e.")
  }
})

test.afterAll(async () => {
  if (idp) await idp.stop()
})

test("SAML SSO round-trip lands the user on /", async ({ page }) => {
  if (!idp) test.skip()

  // 1. Fetch IdP metadata and configure SSO while we still hold the admin
  //    storageState session (set by global-setup before the suite runs).
  const meta = await (await fetch(idp!.metadataUrl)).text()

  const cookies = await page.context().cookies()
  const csrf = cookies.find((c) => c.name === "__Host-csrf")?.value
  if (!csrf) throw new Error("Admin storageState has no CSRF cookie — was global-setup skipped?")

  const patchResp = await page.request.patch("/api/v1/settings/sso", {
    headers: { "X-CSRF-Token": csrf },
    data: { protocol: "saml", samlMetadataXml: meta, enabled: true },
  })
  expect(patchResp.status()).toBe(200)

  // Generate the SP signing keypair so the IdP can verify AuthnRequests.
  const keyResp = await page.request.post("/api/v1/settings/sso/saml/sp-keypair", {
    headers: { "X-CSRF-Token": csrf },
  })
  expect(keyResp.status()).toBe(200)

  // 2. Drop all cookies to simulate an unauthenticated browser session.
  await page.context().clearCookies()

  await page.goto("/login")
  await expect(page.getByRole("link", { name: /Sign in with SSO/i })).toBeVisible()
  await page.getByRole("link", { name: /Sign in with SSO/i }).click()

  // 3. Authenticate at the test IdP (SimpleSAMLphp login form).
  await page.locator("input[name=username]").fill(idp!.username)
  await page.locator("input[name=password]").fill(idp!.password)
  await page.locator("button[type=submit]").click()

  // 4. ACS handler at /auth/sso/saml/acs processes the POST, creates a JIT
  //    session, and issues a 302 to "/". Wait for that navigation to settle.
  await page.waitForURL(/\/$/, { timeout: 15_000 })

  // 5. A session cookie must exist — confirms the round-trip completed.
  const post = await page.context().cookies()
  expect(post.find((c) => c.name === "__Host-session")).toBeTruthy()
})
