"use client"

import { useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/Button"
import { ApiClientError } from "@/lib/client/api-client.types"
import { reverifyFinding } from "@/lib/client/findings-api"
import { cancelScan } from "@/lib/client/scans-api"

/** Triggers a re-scan of the finding's source so the verification pass runs
 *  again. The re-scan is asynchronous and the LLM phase can take several
 *  minutes, so after the request is accepted the button stays in a verifying
 *  state (with a cancel affordance) until the finding re-ingests — detected
 *  via `findingUpdatedAt` changing — rather than flipping to a static line
 *  that reads as done while generation is still running. */
export function ReverifyButton({
  findingId,
  findingUpdatedAt,
}: {
  findingId: number | string
  findingUpdatedAt?: string | null
}) {
  const [state, setState] = useState<"idle" | "loading" | "verifying" | "error">("idle")
  const [error, setError] = useState<string | null>(null)
  const [scanId, setScanId] = useState<string | null>(null)
  // Snapshot the finding's updated_at at the moment the re-scan was kicked
  // off. When the finding re-ingests the prop advances past this and we reset
  // to idle (the advisory has been regenerated).
  const startedAtRef = useRef<string | null>(null)

  useEffect(() => {
    if (state === "verifying" && findingUpdatedAt && startedAtRef.current !== null && findingUpdatedAt !== startedAtRef.current) {
      setState("idle")
      setScanId(null)
      startedAtRef.current = null
    }
  }, [findingUpdatedAt, state])

  // If the user navigates to a different finding, drop any in-flight verifying
  // state so the button doesn't carry a stale scan id forward.
  useEffect(() => {
    setState("idle")
    setScanId(null)
    setError(null)
    startedAtRef.current = null
  }, [findingId])

  async function run() {
    setState("loading")
    setError(null)
    try {
      const res = await reverifyFinding(findingId)
      setScanId(res.scan_id)
      startedAtRef.current = findingUpdatedAt ?? null
      setState("verifying")
    } catch (err) {
      setState("error")
      setError(
        err instanceof ApiClientError && err.message
          ? err.message
          : "Could not start re-scan. Try again.",
      )
    }
  }

  async function cancel() {
    if (!scanId) return
    try {
      await cancelScan(scanId)
    } catch {
      // Idempotent endpoint; a 404 means it already terminalled. Either way
      // the user asked to stop waiting, so drop the verifying state.
    }
    setState("idle")
    setScanId(null)
    startedAtRef.current = null
  }

  if (state === "verifying") {
    return (
      <div className="flex flex-col items-center gap-2">
        <div className="flex items-center gap-2 text-2xs font-mono uppercase tracking-[0.1em] text-[var(--color-text-secondary)]">
          <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-[var(--color-text-tertiary)] border-t-[var(--color-accent)]" aria-hidden="true" />
          Verifying
        </div>
        <p className="max-w-sm text-center text-2xs leading-relaxed text-[var(--color-text-tertiary)]">
          LLM verification is running. Generation time varies per finding and can take several minutes. This finding updates when it completes.
        </p>
        <Button variant="ghost" size="xs" onClick={cancel}>
          Cancel
        </Button>
      </div>
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
