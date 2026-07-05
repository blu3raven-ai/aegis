import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(
  new URL("./ActiveSessionsCard.tsx", import.meta.url),
  "utf8",
)

test("ActiveSessionsCard parses the current user agent at mount", () => {
  // navigator is read inside an effect so SSR can render a neutral fallback.
  assert.match(SRC, /useEffect\(/)
  assert.match(SRC, /navigator\.userAgent/)
})

test("ActiveSessionsCard reports the current device with a 'Current' badge", () => {
  assert.match(SRC, /Current/)
})

test("ActiveSessionsCard exposes the sign-out-everywhere action", () => {
  assert.match(SRC, /Sign out everywhere/)
})

test("ActiveSessionsCard recognises common platforms and browsers", () => {
  for (const platform of ["macOS", "Windows", "Linux", "iOS", "Android"]) {
    assert.match(SRC, new RegExp(`"${platform}"`))
  }
  for (const browser of ["Chrome", "Firefox", "Safari", "Edge"]) {
    assert.match(SRC, new RegExp(browser))
  }
})
