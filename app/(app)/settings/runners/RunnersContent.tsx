"use client"

import { useCallback, useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { RUNNERS_API } from "@/lib/shared/api-paths"
import { AddRunnerModal } from "./AddRunnerModal"
import { RunnerTable } from "./RunnerTable"
import type { Runner } from "./types"
import { useSSE } from "@/components/providers/SSEProvider"

export function RunnersContent({ canEdit }: { canEdit: boolean }) {
  const router = useRouter()
  const [mode, setMode] = useState<"local" | "remote">("local")
  const [runners, setRunners] = useState<Runner[]>([])
  const [showAddModal, setShowAddModal] = useState(false)
  const [loading, setLoading] = useState(true)
  const [confirmModeSwitch, setConfirmModeSwitch] = useState<"local" | "remote" | null>(null)

  const loadRunners = useCallback(async () => {
    try {
      const res = await fetch(RUNNERS_API.list, { cache: "no-store" })
      if (res.ok) {
        const data = await res.json()
        setMode(data.mode || "local")
        setRunners(data.runners || [])
      }
    } catch { /* ignore */ }
    finally { setLoading(false) }
  }, [])

  useEffect(() => {
    void loadRunners()
  }, [loadRunners])

  useSSE("runner.status", () => {
    void loadRunners()
  })

  function requestModeChange(newMode: "local" | "remote") {
    if (newMode === mode) return
    if (mode === "remote" && runners.length > 0) {
      setConfirmModeSwitch(newMode)
      return
    }
    void commitModeChange(newMode)
  }

  async function commitModeChange(newMode: "local" | "remote") {
    setConfirmModeSwitch(null)
    setMode(newMode)
    await fetch(RUNNERS_API.mode, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: newMode }),
    })
  }

  if (loading) {
    return (
      <div className="space-y-8">
        <div className="h-6 w-32 animate-pulse rounded bg-[var(--color-surface-raised)]" />
        <div className="h-24 animate-pulse rounded bg-[var(--color-surface-raised)]" />
      </div>
    )
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">Runners</h2>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          Choose where scans run — on this machine or on dedicated remote runners.
        </p>
      </div>

      {/* Mode toggle */}
      <div className="space-y-4">
        <p className="text-sm font-medium text-[var(--color-text-primary)]">Execution mode</p>
        <div className="grid gap-3 sm:grid-cols-2">
          <button
            type="button"
            disabled={!canEdit}
            onClick={() => requestModeChange("local")}
            className={`rounded-xl border p-4 text-left transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
              mode === "local"
                ? "border-[var(--color-accent)] bg-[var(--color-accent-subtle)]"
                : "border-[var(--color-border)] hover:border-[var(--color-text-secondary)]"
            }`}
          >
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${mode === "local" ? "bg-[var(--color-accent)]" : "bg-[var(--color-text-secondary)]"}`} />
              <span className={`text-sm font-semibold ${mode === "local" ? "text-[var(--color-accent)]" : "text-[var(--color-text-primary)]"}`}>
                Local
              </span>
            </div>
            <p className="mt-2 text-xs leading-relaxed text-[var(--color-text-secondary)]">
              Scanners run as Docker containers on this machine. Simple to set up, but uses local CPU, memory, and storage.
            </p>
          </button>
          <button
            type="button"
            disabled={!canEdit}
            onClick={() => requestModeChange("remote")}
            className={`rounded-xl border p-4 text-left transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
              mode === "remote"
                ? "border-[var(--color-accent)] bg-[var(--color-accent-subtle)]"
                : "border-[var(--color-border)] hover:border-[var(--color-text-secondary)]"
            }`}
          >
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${mode === "remote" ? "bg-[var(--color-accent)]" : "bg-[var(--color-text-secondary)]"}`} />
              <span className={`text-sm font-semibold ${mode === "remote" ? "text-[var(--color-accent)]" : "text-[var(--color-text-primary)]"}`}>
                Remote Runners
              </span>
              <span className="rounded-full bg-[var(--color-surface-raised)] px-2 py-0.5 text-2xs font-semibold uppercase tracking-wider text-[var(--color-text-tertiary)]">
                In development
              </span>
            </div>
            <p className="mt-2 text-xs leading-relaxed text-[var(--color-text-secondary)]">
              Scanners run on separate machines you register as runners. Keeps this portal lightweight and prevents resource issues from large scans. This feature is still being built.
            </p>
          </button>
        </div>
      </div>

      {/* Mode switch confirmation */}
      {confirmModeSwitch && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 dark:border-amber-800 dark:bg-amber-900/20">
          <p className="text-sm font-medium text-amber-800 dark:text-amber-200">Switch to local mode?</p>
          <p className="mt-1 text-xs text-amber-700 dark:text-amber-300">
            {runners.length} runner(s) are registered. Switching to local mode means scans will run on this machine instead.
          </p>
          <div className="mt-3 flex gap-2">
            <button type="button" onClick={() => void commitModeChange(confirmModeSwitch)} className="rounded-lg bg-[var(--color-state-pending)] px-3 py-1.5 text-xs font-semibold text-[var(--color-accent-on)] hover:brightness-110">
              Switch to local
            </button>
            <button type="button" onClick={() => setConfirmModeSwitch(null)} className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-secondary)]">
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Warning banner (remote only) */}
      {mode === "remote" && (
        <div className="flex items-start gap-3 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-900/20 dark:text-amber-200">
          <svg className="mt-0.5 h-4 w-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
          </svg>
          <p>Remote runners are trusted with repository access tokens and registry credentials. Only register runners on machines you control and trust.</p>
        </div>
      )}

      {/* Runner table (same component for both modes) */}
      <RunnerTable
        runners={runners}
        label={mode === "local" ? "Local Runner" : `Runner Pool (${runners.length})`}
        showAddButton={mode === "remote" && canEdit}
        isLocalMode={mode === "local"}
        onAddClick={() => setShowAddModal(true)}
        onRowClick={(r) => router.push(`/settings/runners/${r.id}`)}
      />

      {/* Add runner modal */}
      {showAddModal && (
        <AddRunnerModal
          portalUrl={window.location.origin}
          onClose={() => { setShowAddModal(false); void loadRunners() }}
        />
      )}
    </div>
  )
}
