import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(join(ROOT, "components/layout/PageHeader.tsx"), "utf8")

describe("PageHeader", () => {
  it("accepts icon + title + description + controls props", () => {
    assert.ok(/icon\??:\s*React\.ReactNode/.test(src), "icon prop must exist")
    assert.ok(/title:\s*string/.test(src), "title prop must exist")
    assert.ok(/description\?:\s*string/.test(src), "description prop must exist")
    assert.ok(/controls\?:\s*React\.ReactNode/.test(src), "controls prop must exist")
  })

  it("renders a sticky <header> bounded to the surface token", () => {
    assert.ok(src.includes("<header"), "must be a <header> landmark")
    assert.ok(src.includes("sticky top-0"))
    assert.ok(src.includes("bg-[var(--color-surface)]"))
    assert.ok(src.includes("border-[var(--color-border)]"))
  })

  it("places the title in an h1 and the description in a p", () => {
    assert.ok(/<h1[^>]*>\{title\}<\/h1>/.test(src), "title must be h1")
    assert.ok(/<p[^>]*>\{subtitle\}<\/p>/.test(src) || /\{subtitle &&[^}]*<p/.test(src), "description must be p")
  })

  it("controls slot is right-aligned via ml-auto", () => {
    assert.ok(src.includes("ml-auto"), "controls container must use ml-auto")
  })

  it("uses design-system text tokens (no hardcoded gray/black)", () => {
    assert.ok(!/text-(gray|black|white|slate)-/.test(src), "no hardcoded Tailwind color literals")
    assert.ok(src.includes("var(--color-text-primary)"))
    assert.ok(src.includes("var(--color-text-secondary)"))
  })

  it("keeps backward-compat with deprecated org prop falling back to description", () => {
    assert.ok(/description \|\| org/.test(src), "subtitle resolution must prefer description, fall back to org")
  })
})
