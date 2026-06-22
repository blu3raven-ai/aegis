import { GraphQLClient, ClientError } from "graphql-request"

// graphql-request v7 calls `new URL(url)` internally, which requires an
// absolute URL.  Resolve against window.location.origin in the browser.
const GQL_ENDPOINT =
  typeof window !== "undefined"
    ? `${window.location.origin}/api/v1/graphql`
    : "/api/v1/graphql"

const CSRF_COOKIE_NAME = "__Host-csrf"

const client = new GraphQLClient(GQL_ENDPOINT, {
  credentials: "include",
})

function readCsrfCookie(): string | null {
  if (typeof document === "undefined") return null
  for (const pair of document.cookie.split(";").map((p) => p.trim())) {
    const [k, ...rest] = pair.split("=")
    if (k === CSRF_COOKIE_NAME) return rest.join("=")
  }
  return null
}

export class GraphQLQueryError extends Error {
  constructor(message: string, public code?: string) {
    super(message)
    this.name = "GraphQLQueryError"
  }
}

export async function gqlQuery<T>(query: string, variables?: Record<string, unknown>): Promise<T> {
  const requestHeaders: Record<string, string> = {
    "Content-Type": "application/json",
  }
  const csrf = readCsrfCookie()
  if (csrf !== null) requestHeaders["X-CSRF-Token"] = csrf
  try {
    return await client.request<T>({ document: query, variables, requestHeaders })
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
