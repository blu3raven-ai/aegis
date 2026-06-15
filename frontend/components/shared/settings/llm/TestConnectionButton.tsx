"use client"

import { useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/Button"

type State = "idle" | "testing" | "ok" | "failed"

export function TestConnectionButton() {
  const [state, setState] = useState<State>("idle")
  const [error, setError] = useState<string>("")
  const clearTimer = useRef<number | null>(null)

  // Success auto-clears after 5s. Failures persist until re-test so the
  // user has time to read the error message.
  useEffect(() => {
    if (state === "ok") {
      clearTimer.current = window.setTimeout(() => setState("idle"), 5000)
      return () => {
        if (clearTimer.current) window.clearTimeout(clearTimer.current)
      }
    }
  }, [state])

  async function test() {
    setState("testing")
    setError("")
    try {
      const r = await fetch("/api/v1/settings/llm/test", { method: "POST" })
      if (r.status === 404) {
        setState("failed")
        setError("LLM is not configured. Save your config first.")
        return
      }
      const body = await r.json()
      if (body.ok) {
        setState("ok")
        return
      }
      setState("failed")
      setError(body.detail || body.error || "Unknown error")
    } catch (e) {
      setState("failed")
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <div className="flex items-center gap-3">
      <Button
        variant="secondary"
        size="md"
        onClick={test}
        disabled={state === "testing"}
        isLoading={state === "testing"}
        aria-busy={state === "testing"}
      >
        {state === "testing" ? "Testing…" : "Test connection"}
      </Button>

      {state === "ok" && (
        <span
          role="status"
          aria-live="polite"
          className="inline-flex items-center text-xs font-medium text-[var(--color-status-ok)]"
        >
          ✓ Connected
        </span>
      )}

      {state === "failed" && (
        <span
          role="alert"
          title={error}
          className="inline-flex max-w-xs items-center truncate text-xs font-medium text-[var(--color-severity-critical)]"
        >
          ✕ {error}
        </span>
      )}
    </div>
  )
}
