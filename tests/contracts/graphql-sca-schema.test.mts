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

const findingsQueryMatch = queriesSource.match(/export const DEPENDENCIES_FINDINGS_QUERY = `([\s\S]*?)`/)
assert.ok(findingsQueryMatch, "DEPENDENCIES_FINDINGS_QUERY not found")
const findingsQuery = findingsQueryMatch[1]

test("DEPENDENCIES_FINDINGS_QUERY fields align with ScaFinding Strawberry type", () => {
  const backendFields = extractStrawberryFields("backend/src/graphql/dependencies_resolvers.py", "DependenciesFinding")
  const queryFields = extractQueryFields(findingsQuery, "dependenciesFindings.items")
  const backendCamel = new Set(backendFields.map(snakeToCamel))

  for (const field of queryFields) {
    assert.ok(backendCamel.has(field), `Frontend queries field "${field}" not in backend ScaFinding`)
  }
})

test("DEPENDENCIES_FINDINGS_QUERY filter params match dependencies_findings resolver signature", () => {
  const resolverParams = extractResolverParams("backend/src/graphql/dependencies_resolvers.py", "dependencies_findings")
  const queryParams = extractQueryParams(findingsQuery)
  const resolverCamel = new Set(resolverParams.map(snakeToCamel))

  for (const param of queryParams) {
    assert.ok(resolverCamel.has(param), `Frontend sends param "${param}" not in dependencies_findings()`)
  }
})

test("GqlDependenciesFinding TS interface matches DEPENDENCIES_FINDINGS_QUERY selection set", () => {
  const tsFields = extractTsInterfaceFields("lib/shared/graphql/types.ts", "GqlDependenciesFinding")
  const queryFields = extractQueryFields(findingsQuery, "dependenciesFindings.items")
  const querySet = new Set(queryFields)

  for (const field of tsFields) {
    assert.ok(querySet.has(field), `GqlDependenciesFinding has "${field}" but query doesn't request it`)
  }
})
