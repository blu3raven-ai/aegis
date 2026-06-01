export interface Runner {
  id: string
  name: string
  status: string
  os: string
  arch: string
  registeredAt: string
  approvedAt: string | null
  lastHeartbeatAt: string
  jobsCompleted: number
  maxConcurrent: number
  cpuPercent: number | null
  cores: number | null
  healthPercent: number | null
}

export interface RunnerDetail extends Runner {
  memoryUsedGb: number | null
  memoryTotalGb: number | null
  diskUsedGb: number | null
  diskTotalGb: number | null
}

export interface RunnerJob {
  id: string
  jobType: string
  org: string
  runId: string
  status: string
  createdAt: string
  startedAt: string | null
  completedAt: string | null
}

export interface HeartbeatEntry {
  receivedAt: string
  cpuPercent: number | null
  memoryUsedGb: number | null
}
