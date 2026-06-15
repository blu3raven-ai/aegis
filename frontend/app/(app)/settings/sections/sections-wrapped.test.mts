import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

// Members / Roles / Teams were promoted out of /settings and live at
// /members, /roles, /teams as top-level routes — see app/(app)/{members,
// roles,teams}/page.tsx.
const WRAPS: Array<[file: string, id: string, title: string]> = [
  ["SsoSection.tsx", "sso", "SSO / SAML"],
  ["AuditLogSection.tsx", "audit", "Audit Log"],
  ["ApiKeysSection.tsx", "api-keys", "API tokens"],
  ["RunnersSection.tsx", "runners", "Runners"],
  ["LlmSection.tsx", "llm", "LLM verification"],
  ["LicenseSection.tsx", "license", "License"],
]

for (const [file, id, title] of WRAPS) {
  test(`${file} wraps SettingsSection with id and title`, () => {
    const src = readFileSync(new URL(`./${file}`, import.meta.url), "utf8")
    assert.match(src, /from\s+"@\/components\/settings\/SettingsSection"/)
    assert.match(src, new RegExp(`id="${id}"`))
    assert.match(src, new RegExp(`title="${title}"`))
  })
}
