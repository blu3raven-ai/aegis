import { readFileSync } from "node:fs"
import assert from "node:assert/strict"
import test from "node:test"

const nav = readFileSync(new URL("./SettingsInPageNav.tsx", import.meta.url), "utf8")

test("nav has a dedicated Add-ons cluster with LLM, Advisory Data, and License", () => {
  assert.match(nav, /label:\s*"Add-ons"/)
  const addOns = nav.slice(nav.indexOf('label: "Add-ons"'))
  for (const id of ["llm", "advisory-data", "license"]) {
    assert.match(addOns, new RegExp(`id:\\s*"${id}"`))
  }
})

test("Organization cluster no longer lists the add-on sections", () => {
  const org = nav.slice(
    nav.indexOf('label: "Organization"'),
    nav.indexOf('label: "Add-ons"'),
  )
  for (const id of ["llm", "advisory-data", "license"]) {
    assert.doesNotMatch(org, new RegExp(`id:\\s*"${id}"`))
  }
  // Organization keeps the core org-admin sections.
  for (const id of ["general", "sso", "audit", "runners"]) {
    assert.match(org, new RegExp(`id:\\s*"${id}"`))
  }
})
