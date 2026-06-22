"use client"

import { useEffect, useState } from "react"
import { previewRule, type RulePreviewResponse } from "@/lib/client/rules-api"
import { Button } from "@/components/ui/Button"

interface RulePreviewProps {
  ruleId: string | null
  /**
   * Incrementing this value re-runs the preview. The parent bumps it
   * when the user switches to the Preview tab so the result stays fresh.
   */
  refreshKey?: number
}

type PreviewState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "success"; data: RulePreviewResponse }
  | { status: "error"; message: string }

function matchCountLabel(count: number): string {
  if (count === 0) return "No findings match this rule yet."
  if (count === 1) return "1 finding would match this rule."
  return `${count} findings would match this rule.`
}

export function RulePreview({ ruleId, refreshKey = 0 }: RulePreviewProps) {
  const [state, setState] = useState<PreviewState>({ status: "idle" })
  const [retryCount, setRetryCount] = useState(0)

  useEffect(() => {
    if (ruleId === null) return

    let cancelled = false
    setState({ status: "loading" })

    previewRule(ruleId)
      .then((data) => {
        if (!cancelled) setState({ status: "success", data })
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          const message =
            err instanceof Error ? err.message : "An unexpected error occurred."
          setState({ status: "error", message })
        }
      })

    return () => {
      cancelled = true
    }
  }, [ruleId, refreshKey, retryCount])

  // Create mode — no rule persisted yet
  if (ruleId === null) {
    return (
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-6 text-center">
        <p className="text-sm text-[var(--color-text-secondary)]">
          Save the rule first to dry-run it.
        </p>
        <p className="mt-1 text-xs text-[var(--color-text-tertiary)]">
          Once saved, this tab will show how many findings match the current conditions.
        </p>
      </div>
    )
  }

  if (state.status === "idle" || state.status === "loading") {
    return (
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-6 text-center">
        <p className="text-sm text-[var(--color-text-secondary)]">Running preview…</p>
      </div>
    )
  }

  if (state.status === "error") {
    return (
      <div className="rounded-lg border border-[var(--color-severity-critical)]/30 bg-[var(--color-surface-raised)] px-5 py-5">
        <p className="text-sm text-[var(--color-severity-critical)]">{state.message}</p>
        <Button
          variant="secondary"
          size="sm"
          aria-label="Retry preview"
          onClick={() => setRetryCount((c) => c + 1)}
          className="mt-3"
        >
          Retry
        </Button>
      </div>
    )
  }

  const { matched_count } = state.data

  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-6">
      <p className="text-2xl font-semibold leading-none tabular-nums text-[var(--color-text-primary)]">
        {matched_count}
      </p>
      <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
        {matchCountLabel(matched_count)}
      </p>
      <p className="mt-4 text-xs text-[var(--color-text-tertiary)]">
        P1 backend preview is currently a stub; live counts ship in a later phase.
      </p>
    </div>
  )
}
