import { readFileSync } from "node:fs"
import assert from "node:assert/strict"
import test from "node:test"
import path from "node:path"
import {
  extractStrawberryFields,
  extractResolverParams,
  extractQueryFields,
  extractQueryParams,
  extractTsInterfaceFields,
  snakeToCamel,
} from "./helpers/schema-parser.mts"

const ROOT = path.resolve(import.meta.dirname, "../..")
const queriesSource = readFileSync(path.join(ROOT, "lib/shared/graphql/queries.ts"), "utf-8")

const findingsQueryMatch = queriesSource.match(/export const SAST_FINDINGS_QUERY = `([\s\S]*?)`/)
assert.ok(findingsQueryMatch, "SAST_FINDINGS_QUERY not found")
const findingsQuery = findingsQueryMatch[1]

test("SAST_FINDINGS_QUERY fields align with SastFinding Strawberry type", () => {
  const backendFields = extractStrawberryFields("backend/src/graphql/sast_resolvers.py", "SastFinding")
  const queryFields = extractQueryFields(findingsQuery, "sastFindings.items")
  const backendCamel = new Set(backendFields.map(snakeToCamel))

  for (const field of queryFields) {
    assert.ok(backendCamel.has(field), `Frontend queries field "${field}" not in backend SastFinding`)
  }
})

test("SAST_FINDINGS_QUERY filter params match sast_findings resolver signature", () => {
  const resolverParams = extractResolverParams("backend/src/graphql/sast_resolvers.py", "sast_findings")
  const queryParams = extractQueryParams(findingsQuery)
  const resolverCamel = new Set(resolverParams.map(snakeToCamel))

  for (const param of queryParams) {
    assert.ok(resolverCamel.has(param), `Frontend sends param "${param}" not in sast_findings()`)
  }
})

test("GqlSastFinding TS interface matches SAST_FINDINGS_QUERY selection set", () => {
  const tsFields = extractTsInterfaceFields("lib/shared/graphql/types.ts", "GqlSastFinding")
  const queryFields = extractQueryFields(findingsQuery, "sastFindings.items")
  const querySet = new Set(queryFields)

  for (const field of tsFields) {
    assert.ok(querySet.has(field), `GqlSastFinding has "${field}" but query doesn't request it`)
  }
})
