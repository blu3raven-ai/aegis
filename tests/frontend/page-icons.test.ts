import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(join(ROOT, "lib/shared/ui/page-icons.tsx"), "utf8")

const EXPECTED_ICONS = [
  "FindingsIcon",
  "ChainsIcon",
  "ReposIcon",
  "SbomIcon",
  "ComplianceIcon",
  "SourcesIcon",
  "FleetIcon",
  "InsightsIcon",
  "ActivityIcon",
]

describe("page-icons module", () => {
  for (const name of EXPECTED_ICONS) {
    it(`exports ${name}`, () => {
      const re = new RegExp(`export function ${name}\\(`)
      assert.ok(re.test(src), `${name} must be exported as a named function`)
    })
  }

  it("wraps every icon in an accent IconChip with the design-system tokens", () => {
    assert.ok(src.includes("bg-[var(--color-accent-subtle)]"), "chip background uses accent-subtle token")
    assert.ok(src.includes("text-[var(--color-accent)]"), "icon stroke uses accent token")
    assert.ok(src.includes("rounded-lg"), "chip is rounded-lg")
    assert.ok(src.includes("p-1.5"), "chip padding is p-1.5")
    assert.ok(/w-5\s+h-5|h-5\s+w-5/.test(src), "icon svg is 5x5")
  })

  it("marks SVGs as aria-hidden (icons are decorative companions to the title)", () => {
    assert.ok(src.includes('aria-hidden="true"'), "icons must be aria-hidden — title carries semantics")
  })

  it("uses currentColor stroke so text-* token cascade controls the stroke", () => {
    assert.ok(src.includes('stroke="currentColor"'))
  })

  it("has no hardcoded color literals", () => {
    const stripped = src
      .split("\n")
      .filter((l) => !l.trim().startsWith("//"))
      .join("\n")
    assert.ok(
      !/#[0-9a-fA-F]{3,6}\b/.test(stripped),
      "no hex literals — every color resolves through CSS variables"
    )
    assert.ok(
      !/text-(gray|black|white|slate|blue|red|green|amber)-[0-9]/.test(stripped),
      "no Tailwind color literals"
    )
  })
})
