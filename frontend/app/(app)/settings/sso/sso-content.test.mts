import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./SsoContent.tsx", import.meta.url), "utf8")

test("SsoContent sources state from useSsoSettings", () => {
  assert.match(SRC, /from\s+"@\/lib\/client\/settings\/use-sso-settings"/)
  assert.match(SRC, /useSsoSettings\(\)/)
})

test("SsoContent no longer renders the misleading 'SSO is enforced' banner", () => {
  assert.doesNotMatch(SRC, /SSO is enforced/)
})

test("SsoContent renders an Identity provider card", () => {
  assert.match(SRC, /heading="Identity provider"/)
})

test("SsoContent supports SAML metadata URL or paste-XML inputs", () => {
  assert.match(SRC, /Metadata URL/)
  assert.match(SRC, /Or paste metadata XML/i)
})

test("SsoContent surfaces SP metadata URL with a copy affordance", () => {
  assert.match(SRC, /samlSpMetadataUrl/)
})

test("SsoContent registers with the global SaveBar provider", () => {
  assert.match(SRC, /from\s+"@\/app\/\(app\)\/settings\/save-bar\/SaveBarProvider"/)
  assert.match(SRC, /useSaveBarSection\(/)
})

test("SsoContent calls generateSamlKeypair on demand", () => {
  assert.match(SRC, /generateSamlKeypair\(/)
})

test("SsoContent exposes the signed IdP metadata toggle", () => {
  assert.match(SRC, /Require signed IdP metadata/)
  assert.match(SRC, /samlValidateMetadataSignature/)
})

test("SsoContent renders OIDC option in the protocol select", () => {
  assert.match(SRC, /value="oidc"/)
})

test("SsoContent renders OIDC fields when protocol is oidc", () => {
  assert.match(SRC, /Discovery URL/i)
  assert.match(SRC, /Client ID/i)
  assert.match(SRC, /Client secret/i)
})

test("SsoContent surfaces the OIDC redirect URI", () => {
  assert.match(SRC, /oidcRedirectUri/)
})

test("SsoContent renders the SCIM provisioning card", () => {
  assert.match(SRC, /heading="Provisioning \(SCIM\)"/)
})

test("SsoContent surfaces the SCIM endpoint URL", () => {
  assert.match(SRC, /scimEndpointUrl/)
})

test("SsoContent wires the SCIM token generate action", () => {
  assert.match(SRC, /generateScimToken\(/)
})

test("SsoContent renders the audit log streaming card", () => {
  assert.match(SRC, /heading="Audit log streaming"/)
})

test("SsoContent offers the three audit-stream targets", () => {
  assert.match(SRC, /value="webhook"/)
  assert.match(SRC, /value="splunk_hec"/)
  assert.match(SRC, /value="syslog"/)
})

test("SsoContent wires the test-event action", () => {
  assert.match(SRC, /testAuditStream\(/)
})
