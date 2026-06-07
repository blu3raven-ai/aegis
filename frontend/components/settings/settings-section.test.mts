import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const section = readFileSync(new URL("./SettingsSection.tsx", import.meta.url), "utf8")
const card = readFileSync(new URL("./SettingsCard.tsx", import.meta.url), "utf8")
const row = readFileSync(new URL("./SettingsRow.tsx", import.meta.url), "utf8")
const fieldRow = readFileSync(new URL("./SettingsFieldRow.tsx", import.meta.url), "utf8")

test("SettingsSection accepts id, title, subtitle, children", () => {
  assert.match(section, /id:\s*string/)
  assert.match(section, /title:\s*string/)
  assert.match(section, /subtitle\?:\s*string/)
  assert.match(section, /children:\s*React\.ReactNode/)
})

test("SettingsSection renders the title as a small-caps <h2>", () => {
  assert.match(section, /<h2[^>]*className="[^"]*uppercase/)
})

test("SettingsSection is the outer bordered card", () => {
  // The section wraps children in the outer rounded card; inner sub-cards
  // sit inside as visual wells.
  assert.match(section, /rounded-xl/)
  assert.match(section, /border border-\[var\(--color-border\)\]/)
  assert.match(section, /bg-\[var\(--color-surface\)\]/)
})

test("SettingsCard is the inner sub-card with optional heading", () => {
  assert.match(card, /heading\?:\s*string/)
  // Inner card uses page-background so it visually recedes inside the outer
  // section card.
  assert.match(card, /bg-\[var\(--color-bg\)\]/)
  assert.match(card, /rounded-lg/)
})

test("SettingsRow supports inline and stacked layouts", () => {
  assert.match(row, /layout\?:\s*"inline"\s*\|\s*"stack"/)
})

test("SettingsRow divides itself with a bottom border that drops on the last row", () => {
  assert.match(row, /border-b border-\[var\(--color-border\)\]/)
  assert.match(row, /last:border-b-0/)
})

test("SettingsFieldRow still uses 180px label / 1fr control grid", () => {
  // Older surfaces (ScopeConfigContent, RunnerDetailContent) still consume
  // SettingsFieldRow; keep it untouched until those migrate.
  assert.match(fieldRow, /grid-cols-\[180px_1fr\]/)
})
