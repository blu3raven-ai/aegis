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

const findingsQueryMatch = queriesSource.match(/export const CODE_SCANNING_FINDINGS_QUERY = `([\s\S]*?)`/)
assert.ok(findingsQueryMatch, "CODE_SCANNING_FINDINGS_QUERY not found")
const findingsQuery = findingsQueryMatch[1]

test("CODE_SCANNING_FINDINGS_QUERY fields align with SastFinding Strawberry type", () => {
  const backendFields = extractStrawberryFields("backend/src/graphql/code_scanning_resolvers.py", "CodeScanningFinding")
  const queryFields = extractQueryFields(findingsQuery, "codeScanningFindings.items")
  const backendCamel = new Set(backendFields.map(snakeToCamel))

  for (const field of queryFields) {
    assert.ok(backendCamel.has(field), `Frontend queries field "${field}" not in backend SastFinding`)
  }
})

test("CODE_SCANNING_FINDINGS_QUERY filter params match code_scanning_findings resolver signature", () => {
  const resolverParams = extractResolverParams("backend/src/graphql/code_scanning_resolvers.py", "code_scanning_findings")
  const queryParams = extractQueryParams(findingsQuery)
  const resolverCamel = new Set(resolverParams.map(snakeToCamel))

  for (const param of queryParams) {
    assert.ok(resolverCamel.has(param), `Frontend sends param "${param}" not in code_scanning_findings()`)
  }
})

test("GqlCodeScanningFinding TS interface matches CODE_SCANNING_FINDINGS_QUERY selection set", () => {
  const tsFields = extractTsInterfaceFields("frontend/lib/shared/graphql/types.ts", "GqlCodeScanningFinding")
  const queryFields = extractQueryFields(findingsQuery, "codeScanningFindings.items")
  const querySet = new Set(queryFields)

  for (const field of tsFields) {
    assert.ok(querySet.has(field), `GqlCodeScanningFinding has "${field}" but query doesn't request it`)
  }
})
