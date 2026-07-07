import { readCsrfCookie } from "./csrf.ts"

export class GraphQLQueryError extends Error {
  code?: string

  constructor(message: string, code?: string) {
    super(message)
    this.name = "GraphQLQueryError"
    this.code = code
  }
}

/**
 * True when an error is a user-correctable query-syntax error (e.g. a malformed
 * SBOM boolean search), as opposed to an auth/server failure. Callers use this
 * to surface an inline hint instead of a hard error banner. Pure — safe to
 * unit-test without React.
 */
export function isQuerySyntaxError(err: unknown): boolean {
  return err instanceof GraphQLQueryError && err.code === "BAD_USER_INPUT"
}

/**
 * POST a GraphQL query with credentials + CSRF header, returning the unwrapped
 * `data`. Maps auth failures and query-syntax errors to a {@link GraphQLQueryError}
 * so callers can distinguish user-correctable input from server/auth failures.
 */
export async function gqlQuery<T>(query: string, variables?: Record<string, unknown>): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  }
  const csrf = readCsrfCookie()
  if (csrf !== null) headers["X-CSRF-Token"] = csrf

  const res = await fetch("/api/v1/graphql", {
    method: "POST",
    headers,
    body: JSON.stringify({ query, variables }),
    credentials: "include",
  })
  const body = (await res.json()) as {
    data?: T
    errors?: { message: string; extensions?: { code?: string } }[]
  }
  if (body.errors && body.errors.length > 0) {
    const gqlError = body.errors[0]
    const message = gqlError.message ?? "GraphQL query failed"
    if (message.includes("Unauthorized") || message.includes("Access denied")) {
      throw new GraphQLQueryError(message, "AUTH_ERROR")
    }
    throw new GraphQLQueryError(message, gqlError.extensions?.code)
  }
  if (!body.data) {
    throw new GraphQLQueryError("GraphQL query returned no data")
  }
  return body.data
}
