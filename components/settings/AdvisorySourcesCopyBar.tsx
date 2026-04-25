"use client"

import { useState } from "react"

interface AdvisorySourcesCopyBarProps {
  sourceLabel: string
  onCopy: () => Promise<void>
}

export function AdvisorySourcesCopyBar({ sourceLabel, onCopy }: AdvisorySourcesCopyBarProps) {
  const [state, setState] = useState<"idle" | "copying" | "done" | "error">("idle")
  const [errorMsg, setErrorMsg] = useState("")

  if (state === "done") {
    return (
      <div className="flex items-center gap-2 rounded-2xl border border-emerald-500/30 bg-emerald-500/5 px-4 py-3">
        <svg className="h-4 w-4 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
          <polyline points="20 6 9 17 4 12" />
        </svg>
        <span className="text-sm text-emerald-400">Copied — settings refreshed</span>
      </div>
    )
  }

  return (
    <div className="flex items-center justify-between rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3">
      <span className="text-sm text-[var(--color-text-secondary)]">
        {sourceLabel} has advisory sources configured.
      </span>
      <div className="flex items-center gap-2">
        {state === "error" && (
          <span className="text-xs text-red-400">{errorMsg}</span>
        )}
        <button
          type="button"
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
          className="rounded-lg bg-[var(--color-accent)] px-3 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-[var(--color-accent-hover)] disabled:opacity-50"
        >
          {state === "copying" ? "Copying..." : `Copy from ${sourceLabel}`}
        </button>
      </div>
    </div>
  )
}
