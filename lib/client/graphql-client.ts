import { GraphQLClient, ClientError } from "graphql-request"

// graphql-request v7 calls `new URL(url)` internally, which requires an
// absolute URL.  Resolve against window.location.origin in the browser.
const GQL_ENDPOINT =
  typeof window !== "undefined"
    ? `${window.location.origin}/api/graphql`
    : "/api/graphql"

const client = new GraphQLClient(GQL_ENDPOINT, {
  headers: { "Content-Type": "application/json" },
})

export class GraphQLQueryError extends Error {
  constructor(message: string, public code?: string) {
    super(message)
    this.name = "GraphQLQueryError"
  }
}

export async function gqlQuery<T>(query: string, variables?: Record<string, unknown>): Promise<T> {
  try {
    return await client.request<T>(query, variables)
  } catch (err) {
    if (err instanceof ClientError) {
      const gqlError = err.response?.errors?.[0]
      const message = gqlError?.message ?? "GraphQL query failed"
      if (message.includes("Unauthorized") || message.includes("Access denied")) {
        throw new GraphQLQueryError(message, "AUTH_ERROR")
      }
      throw new GraphQLQueryError(message)
    }
    throw err
  }
}
