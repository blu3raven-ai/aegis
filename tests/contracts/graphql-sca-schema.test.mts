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

const findingsQueryMatch = queriesSource.match(/export const SCA_FINDINGS_QUERY = `([\s\S]*?)`/)
assert.ok(findingsQueryMatch, "SCA_FINDINGS_QUERY not found")
const findingsQuery = findingsQueryMatch[1]

test("SCA_FINDINGS_QUERY fields align with ScaFinding Strawberry type", () => {
  const backendFields = extractStrawberryFields("backend/src/graphql/sca_resolvers.py", "ScaFinding")
  const queryFields = extractQueryFields(findingsQuery, "scaFindings.items")
  const backendCamel = new Set(backendFields.map(snakeToCamel))

  for (const field of queryFields) {
    assert.ok(backendCamel.has(field), `Frontend queries field "${field}" not in backend ScaFinding`)
  }
})

test("SCA_FINDINGS_QUERY filter params match sca_findings resolver signature", () => {
  const resolverParams = extractResolverParams("backend/src/graphql/sca_resolvers.py", "sca_findings")
  const queryParams = extractQueryParams(findingsQuery)
  const resolverCamel = new Set(resolverParams.map(snakeToCamel))

  for (const param of queryParams) {
    assert.ok(resolverCamel.has(param), `Frontend sends param "${param}" not in sca_findings()`)
  }
})

test("GqlScaFinding TS interface matches SCA_FINDINGS_QUERY selection set", () => {
  const tsFields = extractTsInterfaceFields("lib/shared/graphql/types.ts", "GqlScaFinding")
  const queryFields = extractQueryFields(findingsQuery, "scaFindings.items")
  const querySet = new Set(queryFields)

  for (const field of tsFields) {
    assert.ok(querySet.has(field), `GqlScaFinding has "${field}" but query doesn't request it`)
  }
})
