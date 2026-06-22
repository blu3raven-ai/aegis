"use client"

import { useState } from "react"
import { Button } from "@/components/ui/Button"
import { submitScan } from "@/lib/client/sources-api"
import { useHasPermission } from "@/lib/client/use-permission"

interface RescanButtonProps {
  repoId: string
  lastScannedSha: string | null | undefined
  onScanQueued?: () => void
}

type Status = "idle" | "loading" | "queued" | "error"

export function RescanButton({ repoId, lastScannedSha, onScanQueued }: RescanButtonProps) {
  const { allowed } = useHasPermission("run_scans")
  const [status, setStatus] = useState<Status>("idle")
  const [error, setError] = useState<string | null>(null)

  if (!allowed) return null
  if (!lastScannedSha) return null

  async function handleClick() {
    if (!lastScannedSha) return
    setStatus("loading")
    setError(null)
    try {
      await submitScan(repoId, { commitSha: lastScannedSha })
      setStatus("queued")
      onScanQueued?.()
      window.setTimeout(() => setStatus("idle"), 3000)
    } catch (err) {
      setStatus("error")
      setError(err instanceof Error ? err.message : "Scan failed")
      window.setTimeout(() => setStatus("idle"), 4000)
    }
  }

  const label =
    status === "queued" ? "Queued" : status === "error" ? "Failed" : "Rescan"

  return (
    <Button
      variant="ghost"
      size="xs"
      onClick={handleClick}
      isLoading={status === "loading"}
      disabled={status === "loading" || status === "queued"}
      title={
        status === "error"
          ? error ?? "Scan failed"
          : `Rescan ${lastScannedSha.slice(0, 7)}`
      }
    >
      {label}
    </Button>
  )
}
