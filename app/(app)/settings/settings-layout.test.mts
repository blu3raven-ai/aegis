import { readFileSync } from "node:fs"
import assert from "node:assert/strict"
import test from "node:test"

const source = readFileSync(new URL("./layout.tsx", import.meta.url), "utf8")

test("settings layout fetches team count for the workspace nav", () => {
  assert.match(source, /getTeamCountServer/)
  assert.match(source, /teamCount/)
  assert.doesNotMatch(source, /orgCount=\{configuredOrgs\.length/)
})

test("settings layout also fetches role count for the workspace nav", () => {
  assert.match(source, /getRoleCountServer/)
  assert.match(source, /roleCount/)
})
