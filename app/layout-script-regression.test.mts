import assert from "node:assert/strict"
import test from "node:test"
import { readFileSync } from "node:fs"
import path from "node:path"

const layoutPath = path.join(process.cwd(), "app", "layout.tsx")

test("root layout uses next/script instead of a raw script element", () => {
  const source = readFileSync(layoutPath, "utf-8")

  assert.match(source, /from "next\/script"/)
  assert.doesNotMatch(source, /<script[\s>]/)
})
