import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const src = readFileSync(fileURLToPath(new URL("./accepted-risks-api.ts", import.meta.url)), "utf-8")

test("targets the accepted-risks REST resource", () => {
  assert.match(src, /\/api\/v1\/accepted-risks/)
})

test("exposes list/create/update/delete", () => {
  assert.match(src, /export async function listAcceptedRisks/)
  assert.match(src, /export async function createAcceptedRisk/)
  assert.match(src, /export async function updateAcceptedRisk/)
  assert.match(src, /export async function deleteAcceptedRisk/)
})

test("returns the ApiResult shape and reuses apiClient", () => {
  assert.match(src, /ApiResult/)
  assert.match(src, /apiClient/)
})
