"use client"

import { useState } from "react"
import { Button } from "@/components/ui/Button"
import { ApiClientError } from "@/lib/client/api-client.types"
import { reverifyFinding } from "@/lib/client/findings-api"

/** Triggers a re-scan of the finding's source so the verification pass runs
 *  again. Async — reports that the re-scan started; the drawer updates when the
 *  finding re-ingests via the usual findings SSE. */
export function ReverifyButton({ findingId }: { findingId: number | string }) {
  const [state, setState] = useState<"idle" | "loading" | "done" | "error">("idle")
  const [error, setError] = useState<string | null>(null)

  async function run() {
    setState("loading")
    setError(null)
    try {
      await reverifyFinding(findingId)
      setState("done")
    } catch (err) {
      setState("error")
      setError(
        err instanceof ApiClientError && err.message
          ? err.message
          : "Could not start re-scan. Try again.",
      )
    }
  }

  if (state === "done") {
    return (
      <p className="text-2xs font-mono uppercase tracking-[0.1em] text-[var(--color-status-ok-text)]">
        Re-scan started. This finding updates when it completes.
      </p>
    )
  }

  return (
    <div className="flex flex-col items-center gap-1.5">
      <Button variant="primary" size="sm" isLoading={state === "loading"} onClick={run}>
        Retry verification
      </Button>
      {state === "error" && error && (
        <p role="alert" className="text-2xs text-[var(--color-severity-critical-text)]">
          {error}
        </p>
      )}
    </div>
  )
}
