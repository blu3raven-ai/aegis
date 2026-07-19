"use client"

import { useState, useEffect, useRef } from "react"
import { startDependenciesRuns, fetchDependenciesRuns } from "@/lib/client/dependencies-client"
import { Button, Spinner } from "@/components/ui/Button"
import { StepLayout } from "@/components/shared/onboarding/StepLayout"
import { WhileYouWaitCard } from "./WhileYouWaitCard"

type ScanStatus = "idle" | "starting" | "running" | "done" | "error"

const ORG_QUERY = `org=${process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"}`

interface SmokeTestStepProps {
  onNext: (data: { scan_run_id?: string; findings_count?: number }) => void
  onBack: () => void
  onSkip: () => void
  loading?: boolean
}

export function SmokeTestStep({ onNext, onBack, onSkip, loading = false }: SmokeTestStepProps) {
  const [status, setStatus] = useState<ScanStatus>("idle")
  const [findingsCount, setFindingsCount] = useState<number | null>(null)
  const [runId, setRunId] = useState<string | null>(null)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const clearPoll = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }

  useEffect(() => () => clearPoll(), [])

  async function startScan() {
    setStatus("starting")
    setErrorMsg(null)

    const { ok, payload } = await startDependenciesRuns(ORG_QUERY, "full", "full")
    if (!ok || !payload.runs?.length) {
      setStatus("error")
      setErrorMsg(payload.error ?? "Failed to start scan. Check that a runner is online.")
      return
    }

    const rid = payload.runs[0].runId
    setRunId(rid)
    setStatus("running")

    pollRef.current = setInterval(async () => {
      const { ok: pollOk, payload: pollPayload } = await fetchDependenciesRuns(ORG_QUERY)
      if (!pollOk) return

      const latest = pollPayload.latest
      if (!latest) return

      if (latest.status === "completed") {
        clearPoll()
        setFindingsCount(latest.findingsCount ?? 0)
        setStatus("done")
      } else if (latest.status === "failed" || latest.status === "cancelled") {
        clearPoll()
        setStatus("error")
        setErrorMsg(latest.error ?? "Scan failed.")
      }
    }, 3000)
  }

  const canProceed = status === "done" || status === "error"

  return (
    <StepLayout
      title="Run your first scan"
      description="Trigger a dependency scan against your repositories to verify everything is connected."
      onBack={onBack}
      onNext={canProceed ? () => onNext({ scan_run_id: runId ?? undefined, findings_count: findingsCount ?? undefined }) : undefined}
      onSkip={onSkip}
      nextLabel="Continue"
      nextDisabled={!canProceed}
      loading={loading}
    >
      <div className="grid grid-cols-1 gap-6 md:grid-cols-[1fr_320px]">
        <div className="flex flex-col gap-4">
          {status === "idle" && (
            <div className="flex flex-col items-start gap-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-6">
              <p className="text-sm text-[var(--color-text-secondary)]">
                Aegis will scan your connected repositories for known vulnerabilities in third-party dependencies. This usually takes 1–3 minutes.
              </p>
              <Button variant="primary" size="sm" onClick={startScan}>
                Start scan
              </Button>
            </div>
          )}

          {(status === "starting" || status === "running") && (
            <div className="flex items-center gap-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-6">
              <Spinner className="h-5 w-5 shrink-0 text-[var(--color-accent)]" />
              <div>
                <p className="text-sm font-medium text-[var(--color-text-primary)]">
                  {status === "starting" ? "Starting scan…" : "Scan in progress…"}
                </p>
                <p className="text-xs text-[var(--color-text-secondary)]">Polling for results every 3 seconds</p>
              </div>
            </div>
          )}

          {status === "done" && (
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-6">
              <div className="flex items-center gap-3">
                <svg className="h-6 w-6 shrink-0 text-emerald-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
                </svg>
                <div>
                  <p className="text-sm font-medium text-[var(--color-text-primary)]">Scan complete</p>
                  <p className="text-xs text-[var(--color-text-secondary)]">
                    {findingsCount !== null
                      ? `${findingsCount} finding${findingsCount !== 1 ? "s" : ""} detected.`
                      : "Results are ready."}
                  </p>
                </div>
              </div>
            </div>
          )}

          {status === "error" && (
            <div className="rounded-lg border border-[var(--color-severity-high)]/30 bg-[var(--color-severity-high)]/5 p-6">
              <p className="text-sm font-medium text-[var(--color-severity-high)]">Scan failed</p>
              <p className="mt-1 text-xs text-[var(--color-text-secondary)]">{errorMsg}</p>
              <button
                type="button"
                onClick={() => { setStatus("idle"); setErrorMsg(null) }}
                className="mt-3 text-xs text-[var(--color-accent)] hover:underline"
              >
                Try again
              </button>
            </div>
          )}
        </div>

        <WhileYouWaitCard />
      </div>
    </StepLayout>
  )
}
