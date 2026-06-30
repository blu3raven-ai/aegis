import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const hook = readFileSync(new URL("./useActiveSection.ts", import.meta.url), "utf8")
const nav = readFileSync(new URL("./SettingsInPageNav.tsx", import.meta.url), "utf8")

test("useActiveSection accepts ids and an optional rootMargin", () => {
  assert.match(hook, /ids:\s*readonly string\[\]/)
  assert.match(hook, /IntersectionObserver/)
})

test("SettingsInPageNav groups items under Personal and Organization", () => {
  for (const label of ["Personal", "Organization"]) {
    assert.match(nav, new RegExp(`label:\\s*"${label}"`))
  }
})

test("SettingsInPageNav separates groups with a divider", () => {
  // Groups after the first carry a top divider (withDivider).
  assert.match(nav, /withDivider=\{index > 0\}/)
  assert.match(nav, /border-t border-\[var\(--color-border\)\]/)
})

test("SettingsInPageNav uses anchor links to every section id", () => {
  // No #tokens anchor anymore — the Personal API tokens row consolidated into
  // the org-level Security & audit > API tokens row. Members / Roles / Teams
  // were promoted out of /settings to top-level routes.
  for (const id of ["profile", "notifications", "security", "general", "sso", "audit", "api-keys", "runners", "argus", "license"]) {
    assert.match(nav, new RegExp(`#${id}\\b`), `expected nav to link to #${id}`)
  }
})

test("SettingsInPageNav no longer surfaces a duplicate Personal API tokens row", () => {
  assert.doesNotMatch(nav, /href:\s*"#tokens"/)
})

test("SettingsInPageNav is a scrollable sidebar column", () => {
  // The settings shell owns scroll-locking; the nav is a fixed-width column
  // that scrolls internally rather than being position: sticky.
  assert.match(nav, /overflow-y-auto/)
  assert.match(nav, /md:flex md:flex-col/)
})

test("SettingsInPageNav highlights the active section", () => {
  assert.match(nav, /useActiveSection/)
})

test("SettingsInPageNav renders an icon alongside every label", () => {
  const itemRe = /\{\s*id:\s*"[^"]+",\s*href:\s*"#[^"]+",\s*label:\s*"[^"]+",\s*icon:\s*ICONS\./g
  const matches = nav.match(itemRe) ?? []
  assert.equal(matches.length, 10, `expected 10 nav items with icons, found ${matches.length}`)
})

test("SettingsInPageNav marks the icon as decorative for screen readers", () => {
  assert.match(nav, /aria-hidden="true"/)
})
