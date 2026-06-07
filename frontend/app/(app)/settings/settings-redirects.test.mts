import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const REDIRECTS: Array<[file: string, target: string]> = [
  ["account/page.tsx", "/settings#profile"],
  ["users/page.tsx", "/settings#members"],
  ["roles/page.tsx", "/settings#roles"],
  ["organisations/page.tsx", "/settings#teams"],
  ["sso/page.tsx", "/settings#sso"],
  ["audit/page.tsx", "/settings#audit"],
  ["api-keys/page.tsx", "/settings#api-keys"],
  ["runners/page.tsx", "/settings#runners"],
  ["license/page.tsx", "/settings#license"],
  ["notifications/page.tsx", "/integrations"],
  ["notifications/rules/page.tsx", "/integrations"],
  ["integrations/page.tsx", "/integrations"],
]

for (const [file, target] of REDIRECTS) {
  test(`${file} redirects to ${target}`, () => {
    const src = readFileSync(new URL(`./${file}`, import.meta.url), "utf8")
    assert.match(src, /from\s+"next\/navigation"/)
    assert.match(src, new RegExp(`redirect\\("${target.replace(/[/#]/g, (m) => `\\${m}`)}"\\)`))
  })
}
