import { readCsrfCookie } from "./csrf.ts"

/**
 * Error thrown when a GraphQL response carries an `errors[]` entry (or no data).
 * `code` is the `extensions.code` from the first error when present, else null.
 */
export class GqlError extends Error {
  code: string | null
  constructor(message: string, code: string | null) {
    super(message)
    this.name = "GqlError"
    this.code = code
  }
}

/**
 * POST a GraphQL operation to the single backend endpoint with credentials and
 * the CSRF header, returning the unwrapped `data` or throwing {@link GqlError}.
 */
export async function gqlFetch<T>(
  operationName: string,
  query: string,
  variables: Record<string, unknown>,
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  }
  const csrf = readCsrfCookie()
  if (csrf !== null) headers["X-CSRF-Token"] = csrf

  const res = await fetch("/api/v1/graphql", {
    method: "POST",
    headers,
    body: JSON.stringify({ operationName, query, variables }),
    credentials: "include",
  })
  const body = (await res.json()) as {
    data?: T
    errors?: { message: string; extensions?: { code?: string } }[]
  }
  if (body.errors && body.errors.length > 0) {
    const first = body.errors[0]
    throw new GqlError(first.message, first.extensions?.code ?? null)
  }
  if (!body.data) {
    throw new GqlError(`${operationName} returned no data`, null)
  }
  return body.data
}
