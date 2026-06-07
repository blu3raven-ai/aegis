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
const queriesSource = readFileSync(path.join(ROOT, "frontend/lib/shared/graphql/queries.ts"), "utf-8")

const findingsQueryMatch = queriesSource.match(/export const CONTAINER_FINDINGS_QUERY = `([\s\S]*?)`/)
assert.ok(findingsQueryMatch, "CONTAINER_FINDINGS_QUERY not found")
const findingsQuery = findingsQueryMatch[1]

test("CONTAINER_FINDINGS_QUERY fields align with ContainerFinding Strawberry type", () => {
  const backendFields = extractStrawberryFields("backend/src/graphql/containers_resolvers.py", "ContainerFinding")
  const queryFields = extractQueryFields(findingsQuery, "containerFindings.items")
  const backendCamel = new Set(backendFields.map(snakeToCamel))

  for (const field of queryFields) {
    assert.ok(backendCamel.has(field), `Frontend queries field "${field}" not in backend ContainerFinding`)
  }
})

test("CONTAINER_FINDINGS_QUERY filter params match container_findings resolver signature", () => {
  const resolverParams = extractResolverParams("backend/src/graphql/containers_resolvers.py", "container_findings")
  const queryParams = extractQueryParams(findingsQuery)
  const resolverCamel = new Set(resolverParams.map(snakeToCamel))

  for (const param of queryParams) {
    assert.ok(resolverCamel.has(param), `Frontend sends param "${param}" not in container_findings()`)
  }
})

test("GqlContainerFinding TS interface matches CONTAINER_FINDINGS_QUERY selection set", () => {
  const tsFields = extractTsInterfaceFields("frontend/lib/shared/graphql/types.ts", "GqlContainerFinding")
  const queryFields = extractQueryFields(findingsQuery, "containerFindings.items")
  const querySet = new Set(queryFields)

  for (const field of tsFields) {
    assert.ok(querySet.has(field), `GqlContainerFinding has "${field}" but query doesn't request it`)
  }
})
