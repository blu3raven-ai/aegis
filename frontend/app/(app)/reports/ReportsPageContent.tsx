"use client"

import { useState, useEffect, useRef } from "react"
import type { ReportSummary } from "@/lib/client/reports-api"
import { generateReport, listReports, deleteReport } from "@/lib/client/reports-api"
import { ReportTemplateGrid, type ReportTemplateId } from "@/components/reports/ReportTemplateGrid"

function formatBytes(n: number | null): string {
  if (n == null) return "—"
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

function relativeTime(iso: string): string {
  if (!iso) return "—"
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 2) return "just now"
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export function ReportsPageContent() {
  const [reports, setReports] = useState<ReportSummary[]>([])
  const [total, setTotal] = useState(0)
  const [listState, setListState] = useState<"loading" | "ok" | "error">("loading")

  // Generate form
  const [reportType, setReportType] = useState<"findings" | "posture">("findings")
  const [format, setFormat] = useState<"json" | "csv">("csv")
  const [generating, setGenerating] = useState(false)
  const [generateError, setGenerateError] = useState<string | null>(null)

  // Delete
  const [deletingId, setDeletingId] = useState<number | null>(null)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  const formRef = useRef<HTMLDivElement | null>(null)
  const [formHighlighted, setFormHighlighted] = useState(false)

  function handleTemplateSelect(id: ReportTemplateId) {
    if (id === "findings-export") {
      setReportType("findings")
    } else if (id === "posture-snapshot") {
      setReportType("posture")
    } else {
      return
    }
    formRef.current?.scrollIntoView({ behavior: "smooth", block: "start" })
    setFormHighlighted(true)
    window.setTimeout(() => setFormHighlighted(false), 1200)
  }

  useEffect(() => {
    void (async () => {
      try {
        const data = await listReports()
        setReports(data.reports)
        setTotal(data.total)
        setListState("ok")
      } catch {
        setListState("error")
      }
    })()
  }, [])

  async function handleGenerate(e: React.FormEvent) {
    e.preventDefault()
    setGenerating(true)
    setGenerateError(null)
    try {
      const report = await generateReport({
        report_type: reportType,
        format: reportType === "posture" ? "json" : format,
      })
      setReports(prev => [report, ...prev])
      setTotal(prev => prev + 1)
    } catch (err) {
      setGenerateError(err instanceof Error ? err.message : "Generation failed")
    } finally {
      setGenerating(false)
    }
  }

  async function handleDelete(id: number) {
    setDeletingId(id)
    setDeleteError(null)
    try {
      await deleteReport(id)
      setReports(prev => prev.filter(r => r.id !== id))
      setTotal(prev => prev - 1)
    } catch {
      setDeleteError("Failed to delete report. Please try again.")
      const data = await listReports()
      setReports(data.reports)
      setTotal(data.total)
    } finally {
      setDeletingId(null)
    }
  }

  if (listState === "loading") {
    return (
      <div className="px-6 py-5 space-y-5">
        <div className="animate-pulse rounded-2xl bg-[var(--color-surface-raised)] h-28" />
        <div className="animate-pulse rounded-2xl bg-[var(--color-surface-raised)] h-40" />
      </div>
    )
  }

  if (listState === "error") {
    return (
      <div className="px-6 py-5">
        <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-12 text-center">
          <p className="text-sm font-medium text-[var(--color-text-primary)]">Could not load reports</p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">The backend may be unavailable. Check that the server is running and try again.</p>
          <button
            onClick={() => window.location.reload()}
            className="mt-4 rounded-lg border border-[var(--color-border)] px-4 py-1.5 text-sm text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] transition-colors"
          >
            Retry
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="px-6 py-5 space-y-5">
      <ReportTemplateGrid onSelect={handleTemplateSelect} />

      <div
        ref={formRef}
        className={`rounded-2xl border bg-[var(--color-surface)] p-5 transition-shadow ${
          formHighlighted
            ? "border-[var(--color-accent)] shadow-[0_0_0_3px_var(--color-accent-subtle)]"
            : "border-[var(--color-border)]"
        }`}
      >
        <h2 className="text-base font-semibold text-[var(--color-text-primary)] mb-4">Generate new report</h2>
        <form onSubmit={handleGenerate} className="flex flex-col gap-4">
          <div className="flex items-center gap-3">
            <span className="text-sm text-[var(--color-text-secondary)] w-28">Report type</span>
            <div className="flex rounded-lg border border-[var(--color-border)] overflow-hidden">
              {(["findings", "posture"] as const).map(t => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setReportType(t)}
                  className={`px-3 py-1.5 text-sm transition-colors ${
                    reportType === t
                      ? "bg-[var(--color-accent)] text-[var(--color-accent-on)] font-semibold"
                      : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                  }`}
                >
                  {t.charAt(0).toUpperCase() + t.slice(1)}
                </button>
              ))}
            </div>
          </div>

          {reportType === "findings" && (
            <div className="flex items-center gap-3">
              <span className="text-sm text-[var(--color-text-secondary)] w-28">Format</span>
              <div className="flex rounded-lg border border-[var(--color-border)] overflow-hidden">
                {(["csv", "json"] as const).map(f => (
                  <button
                    key={f}
                    type="button"
                    onClick={() => setFormat(f)}
                    className={`px-3 py-1.5 text-sm transition-colors ${
                      format === f
                        ? "bg-[var(--color-accent)] text-[var(--color-accent-on)] font-semibold"
                        : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                    }`}
                  >
                    {f.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>
          )}
          {reportType === "posture" && (
            <p className="text-xs text-[var(--color-text-secondary)]">Posture reports are exported as JSON only.</p>
          )}

          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={generating}
              className="px-4 py-2 rounded-lg bg-[var(--color-accent)] text-[var(--color-accent-on)] text-sm font-semibold disabled:opacity-50 transition-opacity"
            >
              {generating ? "Generating…" : "Generate report"}
            </button>
            {generateError && (
              <p className="text-sm text-[var(--color-severity-critical)]">{generateError}</p>
            )}
          </div>
        </form>
      </div>

      {deleteError && (
        <p className="text-sm text-[var(--color-severity-critical)]">{deleteError}</p>
      )}
      {reports.length === 0 ? (
        <ReportsEmptyState />
      ) : (
      <div className="overflow-auto rounded-2xl border border-[var(--color-border)]">
        <table className="min-w-full divide-y divide-[var(--color-border)] text-sm">
          <thead className="bg-[var(--color-surface-raised)] text-left text-xs uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
            <tr>
              <th className="px-5 py-3">Title</th>
              <th className="px-5 py-3">Type</th>
              <th className="px-5 py-3">Format</th>
              <th className="px-5 py-3">Rows</th>
              <th className="px-5 py-3">Size</th>
              <th className="px-5 py-3">Created</th>
              <th className="px-5 py-3">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--color-border)]">
            {(
              reports.map(report => {
                return (
                  <tr key={report.id} className="transition-colors hover:bg-[var(--color-surface-raised)]">
                    <td className="px-5 py-3.5 max-w-xs truncate text-[var(--color-text-primary)]">{report.title}</td>
                    <td className="px-5 py-3.5">
                      <span className={`rounded px-1.5 py-0.5 text-xs font-semibold ${
                        report.report_type === "findings"
                          ? "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
                          : "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]"
                      }`}>
                        {report.report_type}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-xs uppercase text-[var(--color-text-secondary)]">{report.format}</td>
                    <td className="px-5 py-3.5 tabular-nums text-[var(--color-text-secondary)]">
                      {report.row_count ?? "—"}
                    </td>
                    <td className="px-5 py-3.5 tabular-nums text-[var(--color-text-secondary)]">
                      {formatBytes(report.file_size_bytes)}
                    </td>
                    <td className="px-5 py-3.5 text-[var(--color-text-secondary)]">
                      {relativeTime(report.created_at)}
                    </td>
                    <td className="px-5 py-3.5">
                      <div className="flex items-center gap-2">
                        <a
                          href={report.download_url ?? undefined}
                          download
                          target="_blank"
                          rel="noreferrer"
                          aria-disabled={!report.download_url}
                          className={`text-sm ${report.download_url ? "text-[var(--color-accent)] hover:underline" : "pointer-events-none opacity-40 text-[var(--color-text-secondary)]"}`}
                        >
                          Download
                        </a>
                        <button
                          onClick={() => void handleDelete(report.id)}
                          disabled={deletingId === report.id}
                          className="text-sm text-[var(--color-text-secondary)] hover:text-[var(--color-severity-critical)] disabled:opacity-50 transition-colors"
                          aria-label="Delete report"
                        >
                          {deletingId === report.id ? "…" : "Delete"}
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>
      )}
    </div>
  )
}

function ReportsEmptyState() {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-20 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]">
        <svg className="h-8 w-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M9 12.75 11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 0 1-1.043 3.296 3.745 3.745 0 0 1-3.296 1.043A3.745 3.745 0 0 1 12 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 0 1-3.296-1.043 3.745 3.745 0 0 1-1.043-3.296A3.745 3.745 0 0 1 3 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 0 1 1.043-3.296 3.746 3.746 0 0 1 3.296-1.043A3.746 3.746 0 0 1 12 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 0 1 3.296 1.043 3.746 3.746 0 0 1 1.043 3.296A3.745 3.745 0 0 1 21 12Z" />
        </svg>
      </div>
      <div className="flex flex-col gap-1">
        <p className="text-base font-semibold text-[var(--color-text-primary)]">No reports yet</p>
        <p className="max-w-sm text-sm text-[var(--color-text-secondary)]">Generate your first findings or posture report from the form above.</p>
      </div>
    </div>
  )
}
