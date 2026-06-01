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
  scannerSource: string | null | undefined,
  imageName: string | null | undefined,
  registryImage: string | null | undefined,
): ScannerStatusInfo {
  const name = runnerName || "runner"
  const platform = runnerPlatform || ""
  const isRemote = scannerSource === "registry"
  const img = imageName || "scanner image"
  const regImg = registryImage || ""

  // Fix commands differ between local (compose) and remote runners
  const restartFix = isRemote
    ? `Restart the runner agent on ${name} to retry.`
    : "Restart the runner to rebuild: docker compose restart runner"
  const logsFix = isRemote
    ? `Check the runner logs on ${name} for details.`
    : "View runner logs: docker compose logs runner --tail 50"
  const pullFix = regImg
    ? `Alternatively, pull manually: docker pull ${regImg}`
    : ""

  switch (scannerStatus) {
    case "ready":
      return {
        status: "pass",
        detail: platform
          ? `${img} verified on ${name} (${platform})`
          : `${img} verified on ${name}`,
      }

    case "building":
      return {
        status: "loading",
        detail: isRemote
          ? `Pulling ${regImg || img} on ${name}. This may take a few minutes.`
          : `Building ${img} on ${name}. This happens once on first startup and usually takes a few minutes.`,
      }

    case "missing":
      return {
        status: "fail",
        detail: `${img} is not available on ${name}.`,
        fix: [restartFix, pullFix].filter(Boolean).join("\n"),
      }

    case "invalid":
      return {
        status: "fail",
        detail: `${img} failed signature verification. It may have been tampered with or incorrectly built.`,
        fix: restartFix,
      }

    case "build_failed":
      return {
        status: "fail",
        detail: `${img} failed to build on ${name}.`,
        fix: [logsFix, pullFix].filter(Boolean).join("\n"),
      }

    case "pull_failed":
      return {
        status: "fail",
        detail: `Failed to pull ${regImg || img} from the registry. Check network connection and registry access.`,
        fix: regImg ? `Retry manually: docker pull ${regImg}` : restartFix,
      }

    case "no_runner":
      return {
        status: "fail",
        detail: "No runner is connected. The runner builds and manages scanner images.",
        fix: "Start all services: docker compose up -d",
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
  imageName: string | null
  registryImage: string | null
  signature: string | null
  digest: string | null
}

/** Compute prerequisite items from a scanner prerequisites API response. */
export function computeScannerPrereqItems(data: {
  dockerImagePresent: boolean
  imageName: string
  registryImage?: string
  signature: string | null
  signatureValid: boolean
  digest: string | null
  error: string | null
  scanner_status?: string | null
  scanner_source?: string | null
  runner_name?: string | null
  runner_platform?: string | null
}): ScannerPrerequisiteState {
  // When the API doesn't yet return scanner_status but the image is present and
  // signature-verified, treat it as ready so callers get a "pass" result with
  // runner info rather than the generic "loading" fallback.
  const effectiveStatus =
    data.scanner_status ?? (data.dockerImagePresent && data.signatureValid ? "ready" : null)

  const info = scannerStatusToItem(
    effectiveStatus, data.error, data.runner_name, data.runner_platform,
    data.scanner_source, data.imageName, data.registryImage,
  )
  const items: PrerequisiteItem[] = [
    { label: "Scanner image", status: info.status, detail: info.detail, fix: info.fix },
  ]
  return {
    items,
    canEnable: data.dockerImagePresent && data.signatureValid,
    imageName: data.imageName,
    registryImage: data.registryImage || null,
    signature: data.signature,
    digest: data.digest,
  }
}

