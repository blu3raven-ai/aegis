import { apiClient } from "./api-client.ts"

interface CancelScanResponse {
  ok: boolean
  scanId?: string
  already_terminal?: boolean
}

/**
 * Cancel a queued / running / ingesting scan. Idempotent — a scan that's
 * already in a terminal state returns ok=true with already_terminal=true
 * so the UI can drop its busy indicator without erroring.
 *
 * Backed by POST /api/v1/scans/{scan_id}/cancel which is gated on the
 * `cancel_scans` permission and asset scope. Cancels both the ScanRun row
 * and the matching RunnerJob rows so the runner stops the work on its
 * next progress poll.
 */
export async function cancelScan(scanId: string): Promise<CancelScanResponse> {
  return apiClient<CancelScanResponse>(
    `/api/v1/scans/${encodeURIComponent(scanId)}/cancel`,
    { method: "POST" },
  )
}
