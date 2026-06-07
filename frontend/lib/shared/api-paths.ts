export const CODE_SCANNING_API = {
  history: "/code-scanning/api/history",
  runs: "/code-scanning/api/runs",
  runsLatest: "/code-scanning/api/runs/latest",
  runsCancel: "/code-scanning/api/runs/cancel",
  findingsDismiss: "/code-scanning/api/findings/dismiss",
  findingsReopen: "/code-scanning/api/findings/reopen",
  findingsReview: "/code-scanning/api/findings/review",
} as const
export const DEPENDENCIES_API = {
  history: "/dependencies/api/history",
  runs: "/dependencies/api/runs",
  runsLatest: "/dependencies/api/runs/latest",
  runsCancel: "/dependencies/api/runs/cancel",
  findingsDismiss: "/dependencies/api/findings/dismiss",
  findingsReopen: "/dependencies/api/findings/reopen",
  findingsReview: "/dependencies/api/findings/review",
} as const

export const CONTAINER_SCANNING_API = {
  history: "/container-scanning/api/history",
  runs: "/container-scanning/api/runs",
  runsLatest: "/container-scanning/api/runs/latest",
  runsCancel: "/container-scanning/api/runs/cancel",
  findingsDismiss: "/container-scanning/api/findings/dismiss",
  findingsReopen: "/container-scanning/api/findings/reopen",
  findingsReview: "/container-scanning/api/findings/review",
} as const

export const SECRETS_API = {
  reviewQueue: "/secrets/api/review-queue",
  insights: "/secrets/api/insights",
  health: "/secrets/api/health",
  runs: "/secrets/api/runs",
  runsStart: "/secrets/api/runs",
  runsLatest: "/secrets/api/runs/latest",
  runsCancel: "/secrets/api/runs/cancel",
  codePreview: "/secrets/api/code-preview",
  findingsReview: "/secrets/api/findings/review",
} as const

export const RUNNERS_API = {
  list: "/settings/runners",
  tokens: "/settings/runners/tokens",
  mode: "/settings/runners/mode",
  detail: (id: string) => `/settings/runners/${id}`,
  heartbeats: (id: string) => `/settings/runners/${id}/heartbeats`,
  settings: (id: string) => `/settings/runners/${id}/settings`,
} as const
