import { readFileSync } from "node:fs"
import assert from "node:assert/strict"
import test from "node:test"

test("layout metadata points the favicon to the aegis logo", () => {
  const source = readFileSync(new URL("./layout.tsx", import.meta.url), "utf8")

  assert.match(source, /const DEFAULT_ICON = "https:\/\/aegis\.com\/assets\/logo\/aegis-logo\.png"/)
  assert.match(source, /icons:\s*\{\s*icon:\s*DEFAULT_ICON,\s*\}/)
})
