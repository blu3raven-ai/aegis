"use client"

import { use, useCallback, useEffect, useMemo, useState } from "react"
import { Button } from "@/components/ui/Button"
import { SegmentedControl } from "@/components/ui/SegmentedControl"
import { SbomHeader } from "@/components/shared/sbom/SbomHeader"
import { SbomComponentsTable } from "@/components/shared/sbom/SbomComponentsTable"
import { SbomDependencyTree } from "@/components/shared/sbom/SbomDependencyTree"
import { SbomHistoryDrawer } from "@/components/shared/sbom/SbomHistoryDrawer"
import { EmptySbomState } from "@/components/shared/sbom/EmptySbomState"
import { getRepo } from "@/lib/client/sources-api"
import { ApiClientError } from "@/lib/client/api-client.types.ts"
import {
  fetchSbom,
  fetchSbomHistory,
  fetchComponentVulns,
  parseCycloneDxJson,
  deriveDirectness,
  type SbomFormat,
  type SbomHistoryEntry,
  type ParsedSbom,
  type ComponentVulnsLookup,
} from "@/lib/client/sbom-api"

const EMPTY_VULNS_LOOKUP: ComponentVulnsLookup = { byKey: new Map(), byName: new Map() }

type LoadState = "loading" | "ok" | "empty" | "error"

// History is fetched as a single capped page; at the cap the true count is
// unknown, so the UI shows "N+" rather than asserting an exact total.
const HISTORY_LIMIT = 20

type ToastTone = "ok" | "error"
type ToastState = { message: string; tone: ToastTone }

type ViewMode = "components" | "dependencies"

/**
 * Bottom-right toast. Errors stay until dismissed (auto-dismiss only for the
 * "ok" tone); the tone also drives the icon so success/failure isn't conveyed
 * by colour alone. The announcement itself comes from the always-mounted live
 * region in the page (see `ToastLiveRegion`), not from this conditional node —
 * many AT/browser combos skip content that is present when a live region first
 * mounts.
 */
function Toast({ toast, onDismiss }: { toast: ToastState; onDismiss: () => void }) {
  const { message, tone } = toast
  useEffect(() => {
    if (tone !== "ok") return
    const t = setTimeout(onDismiss, 4000)
    return () => clearTimeout(t)
  }, [tone, onDismiss])

  return (
    <div className="fixed bottom-5 right-5 z-50 flex items-center gap-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3 shadow-[var(--shadow-nav)] text-sm text-[var(--color-text-primary)]">
      {tone === "ok" ? (
        <svg className="h-4 w-4 shrink-0 text-[var(--color-status-ok)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M5 13l4 4L19 7" />
        </svg>
      ) : (
        <svg className="h-4 w-4 shrink-0 text-[var(--color-severity-critical)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
        </svg>
      )}
      {message}
      <button
        type="button"
        onClick={onDismiss}
        className="-mr-1.5 ml-1 flex h-8 w-8 shrink-0 items-center justify-center rounded text-[var(--color-text-tertiary)] hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--color-accent)]"
        aria-label="Dismiss"
      >
        <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M6 18 18 6M6 6l12 12" />
        </svg>
      </button>
    </div>
  )
}

/**
 * Always-mounted screen-reader live region. Keeping it in the DOM at all times
 * (rather than mounting it alongside the toast) is what makes the injected
 * message reliably announced. Success uses role="status" (polite); failures
 * use role="alert" (assertive) so they interrupt.
 */
function ToastLiveRegion({ toast }: { toast: ToastState | null }) {
  const isError = toast?.tone === "error"
  return (
    <>
      <div className="sr-only" role="status">
        {toast && !isError ? toast.message : ""}
      </div>
      <div className="sr-only" role="alert">
        {isError ? toast.message : ""}
      </div>
    </>
  )
}

function ErrorState({ repoName, onRetry }: { repoName: string; onRetry: () => void }) {
  return (
    <div role="alert" className="flex flex-col items-center justify-center gap-4 py-20 text-center">
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
  // `repoId` is the asset UUID; resolve it to the human-readable repo name so the
  // header/empty/error states don't show a raw UUID. Falls back to the id only
  // while the lookup is in flight or if the asset can't be resolved.
  const [resolvedName, setResolvedName] = useState<string | null>(null)
  useEffect(() => {
    let cancelled = false
    getRepo(repoId)
      .then((r) => {
        if (cancelled || !r) return
        setResolvedName(r.display_name || [r.org, r.repo].filter(Boolean).join("/") || null)
      })
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [repoId])
  const repoName = resolvedName ?? decodeURIComponent(repoId)

  const [sbomState, setSbomState] = useState<LoadState>("loading")
  const [parsed, setParsed] = useState<ParsedSbom | null>(null)

  const [vulns, setVulns] = useState<ComponentVulnsLookup>(EMPTY_VULNS_LOOKUP)
  const [vulnsLoading, setVulnsLoading] = useState(true)
  const [vulnsError, setVulnsError] = useState(false)

  const [historyState, setHistoryState] = useState<LoadState>("loading")
  const [history, setHistory] = useState<SbomHistoryEntry[]>([])
  const [historyDrawerOpen, setHistoryDrawerOpen] = useState(false)
  const [selectedHash, setSelectedHash] = useState<string | null>(null)

  const [exportLoading, setExportLoading] = useState(false)
  const [toast, setToast] = useState<ToastState | null>(null)

  const [viewMode, setViewMode] = useState<ViewMode>("components")

  // Direct/transitive/unknown per component bom-ref, from the dependency graph.
  const directness = useMemo(
    () => (parsed ? deriveDirectness(parsed) : new Map()),
    [parsed],
  )

  const loadSbom = useCallback(
    async (hash?: string) => {
      setSbomState("loading")
      try {
        const text = await fetchSbom({ repoId, format: "cyclonedx-json", runId: hash })
        if (!text || text.trim() === "") {
          setSbomState("empty")
          return
        }
        const data = parseCycloneDxJson(text)
        setParsed(data)
        setSbomState(data.components.length === 0 ? "empty" : "ok")
        if (hash) setSelectedHash(hash)
      } catch (err) {
        // A 404 means no SBOM exists for this repo yet (e.g. never scanned) —
        // that's the empty case, not a failure. Only genuine errors (network,
        // 5xx) get the retry screen, so a never-scanned repo reads as "no SBOM
        // yet" rather than a scary "couldn't load".
        if (err instanceof ApiClientError && err.status === 404) {
          setSbomState("empty")
        } else {
          setSbomState("error")
        }
      }
    },
    [repoId],
  )

  const loadVulns = useCallback(async () => {
    setVulnsLoading(true)
    setVulnsError(false)
    try {
      setVulns(await fetchComponentVulns(repoId))
    } catch {
      // Vuln overlay is best-effort; the components table still renders without
      // it. Flag the error so empty cells aren't misread as "no open vulns".
      setVulns(EMPTY_VULNS_LOOKUP)
      setVulnsError(true)
    } finally {
      setVulnsLoading(false)
    }
  }, [repoId])

  const loadHistory = useCallback(async () => {
    setHistoryState("loading")
    try {
      const entries = await fetchSbomHistory(repoId, HISTORY_LIMIT)
      setHistory(entries)
      setHistoryState("ok")
      if (entries.length > 0 && !selectedHash) {
        setSelectedHash(entries[0].run_id)
      }
    } catch {
      setHistoryState("error")
      setHistory([])
    }
  }, [repoId, selectedHash])

  useEffect(() => {
    void loadSbom()
    void loadHistory()
    void loadVulns()
  }, [loadSbom, loadHistory, loadVulns])

  async function handleExport(format: SbomFormat, filename: string) {
    setExportLoading(true)
    try {
      const text = await fetchSbom({ repoId, format, runId: selectedHash ?? undefined })
      const blob = new Blob([text], { type: "application/octet-stream" })
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)
      setToast({ message: "SBOM downloaded", tone: "ok" })
    } catch {
      setToast({ message: "Export failed — please try again", tone: "error" })
    } finally {
      setExportLoading(false)
    }
  }

  function handleSelectVersion(entry: SbomHistoryEntry) {
    setHistoryDrawerOpen(false)
    void loadSbom(entry.run_id)
  }

  const latestEntry = history[0]

  // Nothing to export or browse when the repo has no SBOM and no prior
  // snapshots — drop the header actions so they don't dangle over the empty
  // state. Stay `true` while either load is still in flight to avoid a flash.
  const hasNoSbom =
    sbomState === "empty" && historyState === "ok" && history.length === 0

  return (
    <div className="flex h-full flex-col overflow-hidden bg-[var(--color-bg)]">
      <SbomHeader
        repoName={repoName}
        latestEntry={latestEntry}
        historyCount={history.length}
        historyAtCap={history.length >= HISTORY_LIMIT}
        historyError={historyState === "error"}
        historyLoading={historyState === "loading"}
        onExport={handleExport}
        onHistoryOpen={() => setHistoryDrawerOpen(true)}
        exportLoading={exportLoading}
        showActions={!hasNoSbom}
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
          <div className="flex flex-1 flex-col overflow-hidden p-4 gap-3">
            <div className="flex items-center justify-between gap-3">
              <SegmentedControl<ViewMode>
                ariaLabel="SBOM view"
                value={viewMode}
                onChange={setViewMode}
                options={[
                  { id: "components", label: "Components", count: parsed?.components.length },
                  { id: "dependencies", label: "Dependency tree", count: parsed?.dependencies.length },
                ]}
              />
              {viewMode === "components" && vulnsError && !vulnsLoading && (
                <span
                  className="inline-flex items-center gap-1.5 text-xs text-[var(--color-severity-medium-text)]"
                  title="The vulnerability overlay couldn't be loaded, so component rows show no severity data. Retry by reloading."
                >
                  <svg className="h-3.5 w-3.5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
                  </svg>
                  Vulnerability overlay unavailable
                </span>
              )}
            </div>

            {viewMode === "components" ? (
              <SbomComponentsTable
                components={parsed?.components ?? []}
                loading={sbomState === "loading"}
                vulns={vulns}
                vulnsLoading={vulnsLoading}
                directness={directness}
              />
            ) : (
              <div className="flex-1 overflow-y-auto rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]">
                <SbomDependencyTree
                  components={parsed?.components ?? []}
                  dependencies={parsed?.dependencies ?? []}
                  loading={sbomState === "loading"}
                  rootRef={parsed?.metadata?.componentRef}
                />
              </div>
            )}
          </div>
        )}
      </div>

      {/* History drawer */}
      <SbomHistoryDrawer
        open={historyDrawerOpen}
        onClose={() => setHistoryDrawerOpen(false)}
        history={history}
        atCap={history.length >= HISTORY_LIMIT}
        loading={historyState === "loading"}
        selectedHash={selectedHash}
        onSelectVersion={handleSelectVersion}
      />

      {/* Toast notification + always-mounted SR live region */}
      <ToastLiveRegion toast={toast} />
      {toast && <Toast toast={toast} onDismiss={() => setToast(null)} />}
    </div>
  )
}
