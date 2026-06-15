"use client"

import { use, useCallback, useEffect, useState } from "react"
import { Button } from "@/components/ui/Button"
import { SbomHeader } from "@/components/shared/sbom/SbomHeader"
import { SbomComponentsTable } from "@/components/shared/sbom/SbomComponentsTable"
import { SbomDependencyTree } from "@/components/shared/sbom/SbomDependencyTree"
import { SbomHistoryDrawer } from "@/components/shared/sbom/SbomHistoryDrawer"
import { EmptySbomState } from "@/components/shared/sbom/EmptySbomState"
import {
  fetchSbom,
  fetchSbomHistory,
  parseCycloneDxJson,
  type SbomFormat,
  type SbomHistoryEntry,
  type ParsedSbom,
} from "@/lib/client/sbom-api"

type LoadState = "loading" | "ok" | "empty" | "error"

function Toast({ message, onDismiss }: { message: string; onDismiss: () => void }) {
  useEffect(() => {
    const t = setTimeout(onDismiss, 4000)
    return () => clearTimeout(t)
  }, [onDismiss])

  return (
    <div className="fixed bottom-5 right-5 z-50 flex items-center gap-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3 shadow-[var(--shadow-nav)] text-sm text-[var(--color-text-primary)]">
      <svg className="h-4 w-4 shrink-0 text-[var(--color-status-ok)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
        <path d="M5 13l4 4L19 7" />
      </svg>
      {message}
      <button
        type="button"
        onClick={onDismiss}
        className="ml-1 rounded p-0.5 text-[var(--color-text-tertiary)] hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--color-accent)]"
        aria-label="Dismiss"
      >
        <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
          <path d="M6 18 18 6M6 6l12 12" />
        </svg>
      </button>
    </div>
  )
}

function ErrorState({ repoName, onRetry }: { repoName: string; onRetry: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-20 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-[var(--color-severity-critical)]/10 text-[var(--color-severity-critical)]">
        <svg className="h-8 w-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.2} strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
        </svg>
      </div>
      <div className="flex flex-col gap-1">
        <p className="text-base font-semibold text-[var(--color-text-primary)]">
          Couldn&apos;t load SBOM for {repoName}
        </p>
        <p className="max-w-xs text-sm text-[var(--color-text-secondary)]">
          The dependency scanner may not have run yet, or the SBOM is unavailable.
        </p>
      </div>
      <Button variant="secondary" size="md" onClick={onRetry}>
        Retry
      </Button>
    </div>
  )
}

export function SbomRepoPageContent({ params }: { params: Promise<{ repoId: string }> }) {
  const { repoId } = use(params)
  const repoName = decodeURIComponent(repoId)

  const [sbomState, setSbomState] = useState<LoadState>("loading")
  const [parsed, setParsed] = useState<ParsedSbom | null>(null)

  const [historyState, setHistoryState] = useState<LoadState>("loading")
  const [history, setHistory] = useState<SbomHistoryEntry[]>([])
  const [historyDrawerOpen, setHistoryDrawerOpen] = useState(false)
  const [selectedHash, setSelectedHash] = useState<string | null>(null)

  const [exportLoading, setExportLoading] = useState(false)
  const [toast, setToast] = useState<string | null>(null)

  const loadSbom = useCallback(
    async (hash?: string) => {
      setSbomState("loading")
      try {
        const text = await fetchSbom({ repoId: repoId, format: "cyclonedx-json" })
        if (!text || text.trim() === "") {
          setSbomState("empty")
          return
        }
        const data = parseCycloneDxJson(text)
        setParsed(data)
        setSbomState(data.components.length === 0 ? "empty" : "ok")
        if (hash) setSelectedHash(hash)
      } catch {
        setSbomState("error")
      }
    },
    [repoId],
  )

  const loadHistory = useCallback(async () => {
    setHistoryState("loading")
    try {
      const entries = await fetchSbomHistory(repoId, 20)
      setHistory(entries)
      setHistoryState("ok")
      if (entries.length > 0 && !selectedHash) {
        setSelectedHash(entries[0].manifest_set_hash)
      }
    } catch {
      setHistoryState("error")
      setHistory([])
    }
  }, [repoId, selectedHash])

  useEffect(() => {
    void loadSbom()
    void loadHistory()
  }, [loadSbom, loadHistory])

  async function handleExport(format: SbomFormat, filename: string) {
    setExportLoading(true)
    try {
      const text = await fetchSbom({ repoId: repoId, format })
      const blob = new Blob([text], { type: "application/octet-stream" })
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)
      setToast("SBOM downloaded")
    } catch {
      setToast("Export failed — please try again")
    } finally {
      setExportLoading(false)
    }
  }

  function handleSelectVersion(entry: SbomHistoryEntry) {
    setHistoryDrawerOpen(false)
    void loadSbom(entry.manifest_set_hash)
  }

  const latestEntry = history[0]

  return (
    <div className="flex h-full flex-col overflow-hidden bg-[var(--color-bg)]">
      <SbomHeader
        repoName={repoName}
        latestEntry={latestEntry}
        historyCount={history.length}
        onExport={handleExport}
        onHistoryOpen={() => setHistoryDrawerOpen(true)}
        exportLoading={exportLoading}
      />

      {/* Body */}
      <div className="flex flex-1 overflow-hidden">
        {sbomState === "error" ? (
          <div className="flex flex-1 items-center justify-center">
            <ErrorState repoName={repoName} onRetry={() => void loadSbom()} />
          </div>
        ) : sbomState === "empty" ? (
          <div className="flex flex-1 items-center justify-center">
            <EmptySbomState repoName={repoName} />
          </div>
        ) : (
          <>
            {/* Components table (left / main) */}
            <div className="flex flex-1 flex-col overflow-hidden p-4 gap-3">
              <div className="flex items-center justify-between">
                <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
                  Components
                  {parsed && (
                    <span className="ml-2 font-mono text-[11px] font-normal text-[var(--color-text-tertiary)]">
                      ({parsed.components.length.toLocaleString()})
                    </span>
                  )}
                </h2>
              </div>
              <SbomComponentsTable
                components={parsed?.components ?? []}
                loading={sbomState === "loading"}
              />
            </div>

            {/* Dependency tree (right panel) */}
            <aside className="w-[300px] shrink-0 border-l border-[var(--color-border)] bg-[var(--color-surface)] flex flex-col overflow-hidden">
              <div className="border-b border-[var(--color-border)] px-4 py-3">
                <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
                  Dependencies
                  {parsed && (
                    <span className="ml-2 font-mono text-[11px] font-normal text-[var(--color-text-tertiary)]">
                      ({parsed.dependencies.length})
                    </span>
                  )}
                </h2>
              </div>
              <div className="flex-1 overflow-y-auto">
                <SbomDependencyTree
                  components={parsed?.components ?? []}
                  dependencies={parsed?.dependencies ?? []}
                  loading={sbomState === "loading"}
                />
              </div>
            </aside>
          </>
        )}
      </div>

      {/* History drawer */}
      <SbomHistoryDrawer
        open={historyDrawerOpen}
        onClose={() => setHistoryDrawerOpen(false)}
        history={history}
        loading={historyState === "loading"}
        selectedHash={selectedHash}
        onSelectVersion={handleSelectVersion}
      />

      {/* Toast notification */}
      {toast && <Toast message={toast} onDismiss={() => setToast(null)} />}
    </div>
  )
}
