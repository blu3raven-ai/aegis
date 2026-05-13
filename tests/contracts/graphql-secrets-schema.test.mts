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
const QUERIES_FILE = "lib/shared/graphql/queries.ts"
const TYPES_FILE = "lib/shared/graphql/types.ts"
const RESOLVER_FILE = "backend/src/graphql/secrets_resolvers.py"

const queriesSource = readFileSync(path.join(ROOT, QUERIES_FILE), "utf-8")

// Extract the three query strings
const findingsQueryMatch = queriesSource.match(/export const SECRET_FINDINGS_QUERY = `([\s\S]*?)`/)
const overviewQueryMatch = queriesSource.match(/export const SECRET_OVERVIEW_QUERY = `([\s\S]*?)`/)
const filterOptionsQueryMatch = queriesSource.match(/export const SECRET_FILTER_OPTIONS_QUERY = `([\s\S]*?)`/)

assert.ok(findingsQueryMatch, "SECRET_FINDINGS_QUERY not found")
assert.ok(overviewQueryMatch, "SECRET_OVERVIEW_QUERY not found")
assert.ok(filterOptionsQueryMatch, "SECRET_FILTER_OPTIONS_QUERY not found")

const findingsQuery = findingsQueryMatch[1]
const overviewQuery = overviewQueryMatch[1]
const filterOptionsQuery = filterOptionsQueryMatch[1]

test("SECRET_FINDINGS_QUERY fields align with SecretFinding Strawberry type", () => {
  const backendFields = extractStrawberryFields(RESOLVER_FILE, "SecretFinding")
  const queryFields = extractQueryFields(findingsQuery, "secretFindings.items")

  const backendCamel = new Set(backendFields.map(snakeToCamel))

  for (const field of queryFields) {
    assert.ok(
      backendCamel.has(field),
      `Frontend queries field "${field}" but backend SecretFinding has no matching field. ` +
        `Backend fields: ${[...backendCamel].join(", ")}`
    )
  }
})

test("SECRET_OVERVIEW_QUERY fields align with SecretsOverview Strawberry type", () => {
  const backendFields = extractStrawberryFields(
    "backend/src/graphql/types.py",
    "SecretsOverview"
  )
  const queryFields = extractQueryFields(overviewQuery, "secretsOverview")

  const backendCamel = new Set(backendFields.map(snakeToCamel))

  for (const field of queryFields) {
    assert.ok(
      backendCamel.has(field),
      `Frontend queries field "${field}" but backend SecretsOverview has no matching field`
    )
  }
})

test("SECRET_FILTER_OPTIONS_QUERY fields align with SecretsFilterOptions Strawberry type", () => {
  const backendFields = extractStrawberryFields(
    "backend/src/graphql/types.py",
    "SecretsFilterOptions"
  )
  const queryFields = extractQueryFields(filterOptionsQuery, "secretsFilterOptions")

  const backendCamel = new Set(backendFields.map(snakeToCamel))

  for (const field of queryFields) {
    assert.ok(
      backendCamel.has(field),
      `Frontend queries field "${field}" but backend SecretsFilterOptions has no matching field`
    )
  }
})

test("SECRET_FINDINGS_QUERY filter params match secret_findings resolver signature", () => {
  const resolverParams = extractResolverParams(RESOLVER_FILE, "secret_findings")
  const queryParams = extractQueryParams(findingsQuery)

  const resolverCamel = new Set(resolverParams.map(snakeToCamel))

  for (const param of queryParams) {
    assert.ok(
      resolverCamel.has(param),
      `Frontend sends filter param "${param}" but resolver secret_findings() has no matching parameter. ` +
        `Resolver params: ${[...resolverCamel].join(", ")}`
    )
  }
})

test("GqlSecretFinding TS interface matches SECRET_FINDINGS_QUERY selection set", () => {
  const tsFields = extractTsInterfaceFields(TYPES_FILE, "GqlSecretFinding")
  const queryFields = extractQueryFields(findingsQuery, "secretFindings.items")

  const querySet = new Set(queryFields)

  for (const field of tsFields) {
    assert.ok(
      querySet.has(field),
      `GqlSecretFinding has field "${field}" but SECRET_FINDINGS_QUERY doesn't request it`
    )
  }
})
