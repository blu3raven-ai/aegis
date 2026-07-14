import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const src = readFileSync(fileURLToPath(new URL("./AcceptedRisksSection.tsx", import.meta.url)), "utf-8")

test("uses the shared Button and Input primitives (no raw button)", () => {
  assert.match(src, /import \{ Button \} from "@\/components\/ui\/Button"/)
  assert.match(src, /from "@\/components\/ui\/Input"/)
  assert.doesNotMatch(src, /<button[\s>]/)
})

test("wires the accepted-risks client for list/create/delete", () => {
  assert.match(src, /listAcceptedRisks/)
  assert.match(src, /createAcceptedRisk/)
  assert.match(src, /deleteAcceptedRisk/)
})

test("captures a statement and scopes to the connection", () => {
  assert.match(src, /statement/)
  assert.match(src, /connectionId/)
})
