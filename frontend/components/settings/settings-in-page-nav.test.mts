import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const hook = readFileSync(new URL("./useActiveSection.ts", import.meta.url), "utf8")
const nav = readFileSync(new URL("./SettingsInPageNav.tsx", import.meta.url), "utf8")

test("useActiveSection accepts ids and an optional rootMargin", () => {
  assert.match(hook, /ids:\s*readonly string\[\]/)
  assert.match(hook, /IntersectionObserver/)
})

test("SettingsInPageNav groups Personal at the top and three sub-buckets below", () => {
  for (const label of ["Personal", "Identity & Access", "Security & Audit", "Operations"]) {
    assert.match(nav, new RegExp(`label:\\s*"${label}"`))
  }
})

test("SettingsInPageNav drops the horizontal divider between buckets", () => {
  // Spacing between groups now comes from the group-heading rhythm alone —
  // no extra divider line.
  assert.doesNotMatch(nav, /border-t border-\[var\(--color-border\)\]/)
})

test("SettingsInPageNav uses anchor links to every section id", () => {
  // No #tokens anchor anymore — the Personal API tokens row consolidated into
  // the org-level Security & audit > API tokens row. Members / Roles / Teams
  // were promoted out of /settings to top-level routes.
  for (const id of ["profile", "notifications", "security", "general", "sso", "audit", "api-keys", "runners", "llm", "license"]) {
    assert.match(nav, new RegExp(`#${id}\\b`), `expected nav to link to #${id}`)
  }
})

test("SettingsInPageNav no longer surfaces a duplicate Personal API tokens row", () => {
  assert.doesNotMatch(nav, /href:\s*"#tokens"/)
})

test("SettingsInPageNav is sticky", () => {
  assert.match(nav, /sticky\s/)
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
