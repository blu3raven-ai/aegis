import type { Page } from "@playwright/test"
import {
  DEFAULT_SECRETS_OVERVIEW,
  DEFAULT_SECRET_FINDINGS_CONNECTION,
  DEFAULT_SECRET_FILTER_OPTIONS,
  DEFAULT_SEVERITY_COUNTS,
  MOCK_DEPENDENCIES_FINDING,
  MOCK_CODE_SCANNING_FINDING,
  TEST_ORG,
} from "./test-data"

interface GraphQLBody {
  operationName?: string
  query?: string
  variables?: Record<string, unknown>
}

/**
 * Intercept GraphQL requests and return mock data.
 * Only intercepts POST to /graphql — never auth endpoints.
 */
export async function mockGraphQL(page: Page, overrides?: Record<string, unknown>) {
  await page.route("**/graphql", async (route, request) => {
    if (request.method() !== "POST") return route.continue()

    let body: GraphQLBody = {}
    try {
      body = JSON.parse(request.postData() ?? "{}")
    } catch {
      return route.continue()
    }

    const op = body.operationName ?? ""
    const query = body.query ?? ""

    // Secrets
    if (op === "SecretsOverview" || query.includes("secretsOverview")) {
      return route.fulfill({
        json: { data: { secretsOverview: overrides?.secretsOverview ?? DEFAULT_SECRETS_OVERVIEW } },
      })
    }
    if (op === "SecretFindings" || query.includes("secretFindings")) {
      return route.fulfill({
        json: { data: { secretFindings: overrides?.secretFindings ?? DEFAULT_SECRET_FINDINGS_CONNECTION } },
      })
    }
    if (op === "SecretsFilterOptions" || query.includes("secretsFilterOptions")) {
      return route.fulfill({
        json: { data: { secretsFilterOptions: overrides?.secretsFilterOptions ?? DEFAULT_SECRET_FILTER_OPTIONS } },
      })
    }
    if (op === "SecretCounts" || query.includes("secretCounts")) {
      return route.fulfill({
        json: { data: { secretCounts: overrides?.secretCounts ?? DEFAULT_SEVERITY_COUNTS } },
      })
    }

    // Dependencies
    if (op === "DependenciesCounts" || query.includes("dependenciesCounts")) {
      return route.fulfill({
        json: { data: { dependenciesCounts: overrides?.dependenciesCounts ?? DEFAULT_SEVERITY_COUNTS } },
      })
    }
    if (op === "DependenciesFindings" || query.includes("dependenciesFindings")) {
      return route.fulfill({
        json: {
          data: {
            dependenciesFindings: overrides?.dependenciesFindings ?? {
              items: [MOCK_DEPENDENCIES_FINDING],
              totalCount: 1,
              pageInfo: { hasNextPage: false, hasPreviousPage: false, totalPages: 1 },
            },
          },
        },
      })
    }

    // Code Scanning
    if (op === "CodeScanningCounts" || query.includes("codeScanningCounts")) {
      return route.fulfill({
        json: { data: { codeScanningCounts: overrides?.codeScanningCounts ?? DEFAULT_SEVERITY_COUNTS } },
      })
    }
    if (op === "CodeScanningFindings" || query.includes("codeScanningFindings")) {
      return route.fulfill({
        json: {
          data: {
            codeScanningFindings: overrides?.codeScanningFindings ?? {
              items: [MOCK_CODE_SCANNING_FINDING],
              totalCount: 1,
              pageInfo: { hasNextPage: false, hasPreviousPage: false, totalPages: 1 },
            },
          },
        },
      })
    }

    // Container
    if (op === "ContainerCounts" || query.includes("containerCounts")) {
      return route.fulfill({
        json: { data: { containerCounts: overrides?.containerCounts ?? DEFAULT_SEVERITY_COUNTS } },
      })
    }

    return route.continue()
  })
}

/**
 * Intercept REST API calls used by dashboards.
 * Only intercepts data endpoints — never /auth/login or /auth/me.
 */
export async function mockSecretsREST(page: Page) {
  await page.route("**/secrets/api/runs?*", (route) =>
    route.fulfill({
      json: { latest: null, runs: [], lastCompleted: null },
    })
  )

  await page.route("**/secrets/api/review-queue?*", (route) =>
    route.fulfill({ json: { empty: true, queue: [] } })
  )

  await page.route("**/secrets/api/insights?*", (route) =>
    route.fulfill({ json: { triagePriority: [], trend: [] } })
  )

  await page.route("**/secrets/api/health?*", (route) =>
    route.fulfill({
      json: { empty: true, runHistory: [], coverageGaps: [], scannerHitRates: [] },
    })
  )
}

/** Mock the /auth/me endpoint to return a test admin user. */
export async function mockCurrentUser(page: Page, role: "owner" | "viewer" = "owner") {
  await page.route("**/auth/me", (route) =>
    route.fulfill({
      json: {
        user: {
          id: "e2e-admin",
          username: "e2e-admin",
          email: "e2e-admin@test.local",
          role,
          status: "active",
          totpEnabled: false,
          passwordResetRequired: false,
        },
      },
    })
  )
}
