export interface ScanProgressEvent {
  tool: "dependencies_scanning" | "code_scanning" | "secret_scanning" | "container_scanning" | "iac_scanning"
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

export interface ScanCancelledEvent {
  scanId: string
  scannerTypes: string[]
  org: string
  repoId: string
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

export interface ArgusIntelPushEvent {
  message: string
  chainIds?: string[]
}

/**
 * A scanner's findings changed mid-run — emitted by the preview-ingest step so
 * open views refetch and show findings before the slow verification pass, and
 * again as verdicts land. Carries no completion/notification semantics.
 */
export interface FindingsUpdatedEvent {
  tool: string
  org: string
  runId: string
  preview?: boolean
}

export type SSEEventMap = {
  "scan.progress": ScanProgressEvent
  "scan.completed": ScanCompletedEvent
  "scan.failed": ScanFailedEvent
  "scan.cancelled": ScanCancelledEvent
  "source.synced": SourceSyncedEvent
  "runner.status": RunnerStatusEvent
  "notification.new": NotificationNewEvent
  "argus.intel_push": ArgusIntelPushEvent
  "findings.updated": FindingsUpdatedEvent
}

export type SSEEventType = keyof SSEEventMap
