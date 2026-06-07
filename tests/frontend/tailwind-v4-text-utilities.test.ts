import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync, readdirSync, statSync } from "node:fs"
import { join, extname } from "node:path"

const ROOT = join(import.meta.dirname, "../..")

function collectFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === ".next") continue
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) {
      collectFiles(full, out)
    } else if (extname(entry) === ".ts" || extname(entry) === ".tsx") {
      out.push(full)
    }
  }
  return out
}

// In Tailwind v4, text-[var(--custom-var)] does not generate a font-size utility
// and silently falls back to 16px. Use registered @theme utilities (e.g. text-2xs) instead.
const BANNED = /text-\[var\(--type-/

describe("Tailwind v4 text utility compliance", () => {
  const dirs = ["frontend/app", "frontend/components", "frontend/lib"].map((d) => join(ROOT, d))
  const files = dirs.flatMap((d) => collectFiles(d))

  it("no file uses text-[var(--type-*)] which silently breaks in Tailwind v4", () => {
    const violations: string[] = []

    for (const file of files) {
      const src = readFileSync(file, "utf-8")
      src.split("\n").forEach((line, i) => {
        if (BANNED.test(line)) {
          violations.push(`${file.replace(ROOT + "/", "")}:${i + 1}: ${line.trim()}`)
        }
      })
    }

    assert.deepEqual(
      violations,
      [],
      `Found banned text-[var(--type-*)] usage(s):\n${violations.join("\n")}\n\nUse text-2xs (or other @theme-registered utilities) instead.`
    )
  })
})
