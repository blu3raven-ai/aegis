import test from "node:test"
import assert from "node:assert/strict"

async function loadModule() {
  return import("../../frontend/lib/client/graphql-client.ts")
}

test("isQuerySyntaxError: true for a BAD_USER_INPUT GraphQLQueryError", async () => {
  const { GraphQLQueryError, isQuerySyntaxError } = await loadModule()
  assert.equal(isQuerySyntaxError(new GraphQLQueryError("unknown field", "BAD_USER_INPUT")), true)
})

test("isQuerySyntaxError: false for a plain Error", async () => {
  const { isQuerySyntaxError } = await loadModule()
  assert.equal(isQuerySyntaxError(new Error("boom")), false)
})

test("isQuerySyntaxError: false for a GraphQLQueryError with no code", async () => {
  const { GraphQLQueryError, isQuerySyntaxError } = await loadModule()
  assert.equal(isQuerySyntaxError(new GraphQLQueryError("nope")), false)
})

test("isQuerySyntaxError: false for an AUTH_ERROR GraphQLQueryError", async () => {
  const { GraphQLQueryError, isQuerySyntaxError } = await loadModule()
  assert.equal(isQuerySyntaxError(new GraphQLQueryError("Unauthorized", "AUTH_ERROR")), false)
})

test("isQuerySyntaxError: false for non-error values", async () => {
  const { isQuerySyntaxError } = await loadModule()
  assert.equal(isQuerySyntaxError(null), false)
  assert.equal(isQuerySyntaxError("BAD_USER_INPUT"), false)
  assert.equal(isQuerySyntaxError(undefined), false)
})
