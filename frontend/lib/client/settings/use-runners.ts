"use client"

import { gqlQuery } from "../graphql-client.ts"
import { apiClient } from "../api-client.ts"
import type { Runner, RunnerDetail, RunnerJob, HeartbeatEntry } from "@/app/(app)/settings/runners/types"

const RUNNER_FIELDS = `
  id name status os arch registeredAt approvedAt lastHeartbeatAt
  jobsCompleted maxConcurrent cpuPercent cores healthPercent
`

const RUNNER_DETAIL_FIELDS = `
  id name status os arch registeredAt approvedAt lastHeartbeatAt
  maxConcurrent cpuPercent cores
  memoryUsedGb memoryTotalGb diskUsedGb diskTotalGb
`

const JOB_FIELDS = `
  id jobType org runId status createdAt startedAt completedAt
`

export async function fetchRunners(): Promise<{ mode: string; runners: Runner[] }> {
  const data = await gqlQuery<{ runners: { items: { mode: string; runners: Runner[] } } }>(
    `query ListRunners { runners { items { mode runners { ${RUNNER_FIELDS} } } } }`,
  )
  return data.runners.items
}

export async function fetchRunnerDetail(
  runnerId: string,
): Promise<{ runner: RunnerDetail; recentJobs: RunnerJob[] }> {
  const data = await gqlQuery<{
    runners: { runner: { runner: RunnerDetail; recentJobs: RunnerJob[] } | null }
  }>(
    `query RunnerDetail($runnerId: String!) {
      runners {
        runner(runnerId: $runnerId) {
          runner { ${RUNNER_DETAIL_FIELDS} }
          recentJobs { ${JOB_FIELDS} }
        }
      }
    }`,
    { runnerId },
  )
  if (!data.runners.runner) throw new Error("Runner not found")
  return { runner: data.runners.runner.runner, recentJobs: data.runners.runner.recentJobs }
}

export async function fetchRunnerHeartbeats(runnerId: string): Promise<HeartbeatEntry[]> {
  const data = await gqlQuery<{ runners: { heartbeats: HeartbeatEntry[] } }>(
    `query RunnerHeartbeats($runnerId: String!) {
      runners {
        heartbeats(runnerId: $runnerId) { receivedAt cpuPercent memoryUsedGb }
      }
    }`,
    { runnerId },
  )
  return data.runners.heartbeats
}

export async function generateRunnerToken(): Promise<{ token: string; expiresAt: string }> {
  return apiClient<{ token: string; expiresAt: string }>("/api/v1/runners/tokens", {
    method: "POST",
  })
}

export async function setRunnerMode(mode: "local" | "remote"): Promise<void> {
  await apiClient<{ ok: boolean; mode: string }>("/api/v1/runners/mode", {
    method: "POST",
    body: { mode },
  })
}

export async function saveRunnerSettings(
  runnerId: string,
  settings: { maxConcurrent?: number; name?: string },
): Promise<Runner> {
  return apiClient<Runner>(`/api/v1/runners/${encodeURIComponent(runnerId)}/settings`, {
    method: "PATCH",
    body: settings,
  })
}

export async function approveRunner(runnerId: string): Promise<void> {
  await apiClient<{ ok: boolean }>(`/api/v1/runners/${encodeURIComponent(runnerId)}/approve`, {
    method: "POST",
  })
}

export async function revokeRunner(runnerId: string): Promise<void> {
  await apiClient<{ ok: boolean }>(`/api/v1/runners/${encodeURIComponent(runnerId)}/revoke`, {
    method: "POST",
  })
}

export async function deleteRunner(runnerId: string): Promise<void> {
  await apiClient<{ ok: boolean }>(`/api/v1/runners/${encodeURIComponent(runnerId)}`, {
    method: "DELETE",
  })
}

export async function rotateRunnerToken(runnerId: string): Promise<string> {
  const data = await apiClient<{ ok: boolean; newToken: string }>(
    `/api/v1/runners/${encodeURIComponent(runnerId)}/rotate-token`,
    { method: "POST" },
  )
  return data.newToken
}
