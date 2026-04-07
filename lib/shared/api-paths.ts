export const CODE_SCANNING_API = {
  history: "/api/code/history",
  runs: "/api/code/runs",
  runsLatest: "/api/code/runs/latest",
  runsCancel: "/api/code/runs/cancel",
  findingsDismiss: "/api/code/findings/dismiss",
  findingsReopen: "/api/code/findings/reopen",
  findingsReview: "/api/code/findings/review",
} as const
export const DEPENDENCIES_API = {
  history: "/api/dependencies/history",
  runs: "/api/dependencies/runs",
  runsLatest: "/api/dependencies/runs/latest",
  runsCancel: "/api/dependencies/runs/cancel",
  findingsDismiss: "/api/dependencies/findings/dismiss",
  findingsReopen: "/api/dependencies/findings/reopen",
  findingsReview: "/api/dependencies/findings/review",
} as const

export const CONTAINER_SCANNING_API = {
  history: "/api/container-scanning/history",
  runs: "/api/container-scanning/runs",
  runsLatest: "/api/container-scanning/runs/latest",
  runsCancel: "/api/container-scanning/runs/cancel",
  findingsDismiss: "/api/container-scanning/findings/dismiss",
  findingsReopen: "/api/container-scanning/findings/reopen",
  findingsReview: "/api/container-scanning/findings/review",
} as const

export const SECRETS_API = {
  reviewQueue: "/api/secrets/review-queue",
  insights: "/api/secrets/insights",
  health: "/api/secrets/health",
  runs: "/api/secrets/runs",
  runsStart: "/api/secrets/runs",
  runsLatest: "/api/secrets/runs/latest",
  runsCancel: "/api/secrets/runs/cancel",
  codePreview: "/api/secrets/code-preview",
  findingsReview: "/api/secrets/findings/review",
} as const

export const RUNNERS_API = {
  list: "/api/runners",
  tokens: "/api/runners/tokens",
  mode: "/api/runners/mode",
  detail: (id: string) => `/api/runners/${id}`,
  heartbeats: (id: string) => `/api/runners/${id}/heartbeats`,
  settings: (id: string) => `/api/runners/${id}/settings`,
} as const
