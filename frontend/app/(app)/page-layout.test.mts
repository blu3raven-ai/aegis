import test from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import path from "node:path"

const dir = path.join(process.cwd(), "app/(app)")

test("AppSidebar persists collapse state to localStorage", () => {
  const source = readFileSync(path.join(dir, "AppSidebar.tsx"), "utf8")
  assert.match(source, /localStorage/)
  assert.match(source, /sidebar-collapsed/)
})

test("AppSidebar has transition-[width] for collapse animation", () => {
  const source = readFileSync(path.join(dir, "AppSidebar.tsx"), "utf8")
  assert.match(source, /transition-\[width\]/)
})

test("home page has no tool card grid", () => {
  const source = readFileSync(path.join(dir, "page.tsx"), "utf8")
  assert.doesNotMatch(source, /lg:grid-cols-3/)
  assert.doesNotMatch(source, /grid-cols/)
})

