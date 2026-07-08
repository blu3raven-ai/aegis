export const CODE_SCANNING_API = {
  history: "/api/v1/code-scanning/history",
  runs: "/api/v1/code-scanning/runs",
  runsLatest: "/api/v1/code-scanning/runs/latest",
  runsCancel: "/api/v1/code-scanning/runs/cancel",
  findingsDismiss: "/api/v1/code-scanning/findings/dismiss",
  findingsReopen: "/api/v1/code-scanning/findings/reopen",
  findingsReview: "/api/v1/code-scanning/findings/review",
} as const
export const DEPENDENCIES_API = {
  history: "/api/v1/dependencies/history",
  runs: "/api/v1/dependencies/runs",
  runsLatest: "/api/v1/dependencies/runs/latest",
  runsCancel: "/api/v1/dependencies/runs/cancel",
  findingsDismiss: "/api/v1/dependencies/findings/dismiss",
  findingsReopen: "/api/v1/dependencies/findings/reopen",
  findingsReview: "/api/v1/dependencies/findings/review",
} as const

export const CONTAINER_SCANNING_API = {
  history: "/api/v1/container-scanning/history",
  runs: "/api/v1/container-scanning/runs",
  runsLatest: "/api/v1/container-scanning/runs/latest",
  runsCancel: "/api/v1/container-scanning/runs/cancel",
  findingsDismiss: "/api/v1/container-scanning/findings/dismiss",
  findingsReopen: "/api/v1/container-scanning/findings/reopen",
  findingsReview: "/api/v1/container-scanning/findings/review",
} as const

export const SECRETS_API = {
  reviewQueue: "/api/v1/secrets/review-queue",
  insights: "/api/v1/secrets/insights",
  health: "/api/v1/secrets/health",
  runs: "/api/v1/secrets/runs",
  runsStart: "/api/v1/secrets/runs",
  runsLatest: "/api/v1/secrets/runs/latest",
  runsCancel: "/api/v1/secrets/runs/cancel",
  codePreview: "/api/v1/secrets/code-preview",
  findingsReview: "/api/v1/secrets/findings/review",
} as const

export const RUNNERS_API = {
  list: "/api/v1/runners",
  tokens: "/api/v1/runners/tokens",
  detail: (id: string) => `/api/v1/runners/${id}`,
  heartbeats: (id: string) => `/api/v1/runners/${id}/heartbeats`,
  settings: (id: string) => `/api/v1/runners/${id}/settings`,
} as const
