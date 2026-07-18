"use client"

import { useState } from "react"
import { Button } from "@/components/ui/Button"

interface AdvisorySourcesCopyBarProps {
  sourceLabel: string
  onCopy: () => Promise<void>
}

export function AdvisorySourcesCopyBar({ sourceLabel, onCopy }: AdvisorySourcesCopyBarProps) {
  const [state, setState] = useState<"idle" | "copying" | "done" | "error">("idle")
  const [errorMsg, setErrorMsg] = useState("")

  if (state === "done") {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-[var(--color-status-ok-border)] bg-[var(--color-status-ok-subtle)] px-4 py-3">
        <svg className="h-4 w-4 text-[var(--color-status-ok)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
          <polyline points="20 6 9 17 4 12" />
        </svg>
        <span className="text-sm text-[var(--color-status-ok)]">Copied · settings refreshed</span>
      </div>
    )
  }

  return (
    <div className="flex items-center justify-between rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3">
      <span className="text-sm text-[var(--color-text-secondary)]">
        {sourceLabel} has advisory sources configured.
      </span>
      <div className="flex items-center gap-2">
        {state === "error" && (
          <span className="text-xs text-[var(--color-severity-critical)]">{errorMsg}</span>
        )}
        <Button
          variant="primary"
          size="sm"
          isLoading={state === "copying"}
          disabled={state === "copying"}
          onClick={async () => {
            setState("copying")
            setErrorMsg("")
            try {
              await onCopy()
              setState("done")
            } catch (e) {
              setErrorMsg(e instanceof Error ? e.message : "Copy failed")
              setState("error")
            }
          }}
        >
          {state === "copying" ? "Copying" : `Copy from ${sourceLabel}`}
        </Button>
      </div>
    </div>
  )
}
