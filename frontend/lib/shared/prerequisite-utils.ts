export type PrerequisiteItem = {
  label: string
  status: "pass" | "fail" | "loading"
  detail?: string | null
  fix?: string | null
  orgName?: string | null
}

// --- Shared guidance messages per scanner_status ---

type ScannerStatusInfo = {
  status: "pass" | "fail" | "loading"
  detail: string
  fix?: string
}

function scannerStatusToItem(
  scannerStatus: string | null | undefined,
  error: string | null | undefined,
  runnerName: string | null | undefined,
  runnerPlatform: string | null | undefined,
): ScannerStatusInfo {
  const name = runnerName || "runner"
  const platform = runnerPlatform || ""

  switch (scannerStatus) {
    case "ready":
      return {
        status: "pass",
        detail: platform
          ? `Runner ${name} connected (${platform})`
          : `Runner ${name} connected`,
      }

    case "no_runner":
      return {
        status: "fail",
        detail: "No runner is connected. Connect a runner to enable this scanner.",
      }

    default:
      return {
        status: error ? "fail" : "loading",
        detail: error || "Checking scanner status...",
      }
  }
}

// --- Single compute function for all scanner types ---

export type ScannerPrerequisiteState = {
  items: PrerequisiteItem[]
  canEnable: boolean
}

/** Compute prerequisite items from a scanner prerequisites API response. */
export function computeScannerPrereqItems(data: {
  runner_connected: boolean
  error: string | null
  scanner_status?: string | null
  runner_name?: string | null
  runner_platform?: string | null
}): ScannerPrerequisiteState {
  const info = scannerStatusToItem(
    data.scanner_status ?? (data.runner_connected ? "ready" : "no_runner"),
    data.error, data.runner_name, data.runner_platform,
  )
  const items: PrerequisiteItem[] = [
    { label: "Scanner", status: info.status, detail: info.detail, fix: info.fix },
  ]
  return {
    items,
    canEnable: data.runner_connected,
  }
}

