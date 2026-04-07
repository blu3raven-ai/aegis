export interface ScanProgressEvent {
  tool: "dependencies" | "code_scanning" | "secrets" | "container_scanning"
  org: string
  runId: string
  progress: {
    percent: number
    scannedRepos: number
    finishedRepos: number
    expectedRepos: number
    currentRepo: string | null
    stage: string
  }
  logTail: string[]
}

export interface ScanCompletedEvent {
  tool: string
  org: string
  runId: string
  counts?: { total: number; critical: number; high: number; medium: number; low: number }
  duration?: number
}

export interface ScanFailedEvent {
  tool: string
  org: string
  runId: string
  error: string
}

export interface SourceSyncedEvent {
  connectionId: string
  status: "connected" | "disconnected"
  discoveredCount: number | null
  message: string
}

export interface RunnerStatusEvent {
  runnerId: string
  name: string
  status: "online" | "offline"
  lastHeartbeat: string
}

export interface NotificationNewEvent {
  id: string
  title: string
  severity: string
  category: string
  message: string
}

export type SSEEventMap = {
  "scan.progress": ScanProgressEvent
  "scan.completed": ScanCompletedEvent
  "scan.failed": ScanFailedEvent
  "source.synced": SourceSyncedEvent
  "runner.status": RunnerStatusEvent
  "notification.new": NotificationNewEvent
}

export type SSEEventType = keyof SSEEventMap
