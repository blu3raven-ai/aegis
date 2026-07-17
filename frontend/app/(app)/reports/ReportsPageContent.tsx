"use client"

import { useState, useEffect, useRef, useCallback } from "react"
import type { ReportSummary } from "@/lib/client/reports-api"
import { generateReport, listReports, deleteReport } from "@/lib/client/reports-api"
import { listFrameworks } from "@/lib/client/compliance-api"
import { ReportTemplateGrid, type ReportTemplateId } from "@/components/reports/ReportTemplateGrid"
import {
  type ReportType,
  type ReportFormat,
  REPORT_TYPE_OPTIONS,
  formatOptionsForType,
  clampFormat,
  reportTypeLabel,
} from "@/lib/shared/report-types"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { SegmentedControl } from "@/components/ui/SegmentedControl"
import { FilterChip } from "@/components/ui/FilterChip"
import { Skeleton } from "@/components/ui/Skeleton"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"
import { StatusPill, type Status } from "@/components/ui/StatusPill"
import { ScheduledReportsPanel } from "./ScheduledReportsPanel"

// A report row's status drives whether its download is usable; surface it so a
// failed generation isn't a silent dead "Download" link.
const REPORT_STATUS: Record<string, { tone: Status; label: string }> = {
  completed: { tone: "healthy", label: "Ready" },
  pending: { tone: "warning", label: "Generating" },
  failed: { tone: "failing", label: "Failed" },
}

// Per-type badge tint so the report kind reads at a glance in the history table.
const TYPE_BADGE: Record<string, string> = {
  findings: "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]",
  posture: "bg-[var(--color-severity-low-subtle)] text-[var(--color-severity-low-text)]",
  executive: "bg-[var(--color-severity-medium-subtle)] text-[var(--color-severity-medium-text)]",
  risk_register: "bg-[var(--color-severity-high-subtle)] text-[var(--color-severity-high-text)]",
  soc2_evidence: "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]",
}

const SEVERITIES = ["critical", "high", "medium", "low"] as const
type Severity = (typeof SEVERITIES)[number]

// Framework slug used by the PCI attestation shortcut and its download endpoint.
const PCI_DSS_FRAMEWORK = "pci-dss"

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
  const [reportType, setReportType] = useState<ReportType>("findings")
  const [format, setFormat] = useState<ReportFormat>("csv")
  const [severity, setSeverity] = useState<Severity[]>([])
  const [generating, setGenerating] = useState(false)
  const [generateError, setGenerateError] = useState<string | null>(null)

  // PCI attestation shortcut — a direct compliance-attestation download,
  // gated on the PCI DSS framework being tracked (null = not yet known).
  const [attestationBusy, setAttestationBusy] = useState(false)
  const [attestationError, setAttestationError] = useState<string | null>(null)
  const [pciTracked, setPciTracked] = useState<boolean | null>(null)

  // Delete
  const [deletingId, setDeletingId] = useState<number | null>(null)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  const formRef = useRef<HTMLDivElement | null>(null)
  const [formHighlighted, setFormHighlighted] = useState(false)

  // The PCI attestation is the compliance attestation for the PCI DSS framework,
  // reused directly rather than minting a second generator. Fetch it first so a
  // missing framework (or any server error) surfaces a message instead of the
  // browser silently saving the error body as a broken "attestation.pdf".
  async function downloadPciAttestation() {
    setAttestationError(null)
    setAttestationBusy(true)
    try {
      const res = await fetch("/api/v1/compliance/frameworks/pci-dss/attestation.pdf", {
        credentials: "include",
        headers: { Accept: "application/pdf" },
      })
      if (!res.ok) {
        throw new Error(
          res.status === 404
            ? "PCI DSS isn’t a tracked framework yet — add it under Compliance to export its attestation."
            : "Couldn’t generate the PCI DSS attestation. Please try again.",
        )
      }
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = "pci-dss-attestation.pdf"
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      setAttestationError(err instanceof Error ? err.message : "Attestation download failed.")
    } finally {
      setAttestationBusy(false)
    }
  }

  function handleTemplateSelect(id: ReportTemplateId) {
    if (id === "findings-export") {
      setReportType("findings")
      setFormat((f) => clampFormat("findings", f))
    } else if (id === "posture-snapshot") {
      setReportType("posture")
      setFormat((f) => clampFormat("posture", f))
    } else if (id === "monthly-executive") {
      setReportType("executive")
      setFormat((f) => clampFormat("executive", f))
    } else if (id === "quarterly-risk") {
      setReportType("risk_register")
      setFormat((f) => clampFormat("risk_register", f))
    } else if (id === "soc2-evidence") {
      setReportType("soc2_evidence")
      setFormat((f) => clampFormat("soc2_evidence", f))
    } else if (id === "pci-attestation") {
      void downloadPciAttestation()
      return
    } else {
      return
    }
    formRef.current?.scrollIntoView({ behavior: "smooth", block: "start" })
    setFormHighlighted(true)
    window.setTimeout(() => setFormHighlighted(false), 1200)
  }

  const loadReports = useCallback(async () => {
    setListState("loading")
    try {
      const data = await listReports()
      setReports(data.reports)
      setTotal(data.total)
      setListState("ok")
    } catch {
      setListState("error")
    }
  }, [])

  useEffect(() => {
    void loadReports()
  }, [loadReports])

  // Resolve whether PCI DSS is tracked so the attestation card can be gated.
  // On failure leave it null (optimistic) — the download itself fails loudly.
  useEffect(() => {
    let active = true
    listFrameworks()
      .then((frameworks) => {
        if (active) setPciTracked(frameworks.some((f) => f.id === PCI_DSS_FRAMEWORK))
      })
      .catch(() => { if (active) setPciTracked(null) })
    return () => { active = false }
  }, [])

  async function handleGenerate(e: React.FormEvent) {
    e.preventDefault()
    setGenerating(true)
    setGenerateError(null)
    try {
      const report = await generateReport({
        report_type: reportType,
        format: format,
        ...(reportType === "findings" && severity.length > 0
          ? { filters: { severity } }
          : {}),
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
      <div className="px-6 py-6 space-y-5">
        <Skeleton className="rounded-lg h-28" />
        <Skeleton className="rounded-lg h-40" />
      </div>
    )
  }

  if (listState === "error") {
    return (
      <div className="px-6 py-6">
        <Card padding="none" className="px-6 py-12 text-center">
          <p className="text-sm font-medium text-[var(--color-text-primary)]">Could not load reports</p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">The backend may be unavailable. Check that the server is running and try again.</p>
          <div className="mt-4 flex justify-center">
            <Button variant="secondary" onClick={() => void loadReports()}>
              Retry
            </Button>
          </div>
        </Card>
      </div>
    )
  }

  return (
    <div className="px-6 py-6 space-y-5">
      <ReportTemplateGrid
        onSelect={handleTemplateSelect}
        disabledReasons={
          pciTracked === false
            ? { "pci-attestation": "Track PCI DSS in Compliance to enable" }
            : undefined
        }
      />

      {attestationBusy && (
        <p role="status" className="text-sm text-[var(--color-text-secondary)]">
          Preparing PCI DSS attestation…
        </p>
      )}
      {attestationError && (
        <p role="alert" className="text-sm text-[var(--color-severity-critical-text)]">
          {attestationError}
        </p>
      )}

      <div
        ref={formRef}
        className={`rounded-md border bg-[var(--color-surface)] p-5 transition-shadow ${
          formHighlighted
            ? "border-[var(--color-accent)] shadow-[0_0_0_3px_var(--color-accent-subtle)]"
            : "border-[var(--color-border)]"
        }`}
      >
        <h2 className="text-base font-semibold text-[var(--color-text-primary)] mb-4">Generate new report</h2>
        <form onSubmit={handleGenerate} className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <span className="text-sm text-[var(--color-text-secondary)] w-28">Report type</span>
            <SegmentedControl
              ariaLabel="Report type"
              value={reportType}
              onChange={(t) => {
                const next = t as ReportType
                setReportType(next)
                setFormat((f) => clampFormat(next, f))
              }}
              options={REPORT_TYPE_OPTIONS}
            />
          </div>

          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <span className="w-28 text-sm text-[var(--color-text-secondary)]">Format</span>
            <SegmentedControl
              ariaLabel="Format"
              value={format}
              onChange={(f) => setFormat(f as ReportFormat)}
              options={formatOptionsForType(reportType)}
            />
          </div>

          {reportType === "findings" && (
            <div className="flex items-start gap-3">
              <span className="w-28 pt-1 text-sm text-[var(--color-text-secondary)]">Severity</span>
              <div className="flex flex-wrap gap-1.5">
                {SEVERITIES.map((s) => {
                  const active = severity.includes(s)
                  return (
                    <FilterChip
                      key={s}
                      label={s.charAt(0).toUpperCase() + s.slice(1)}
                      active={active}
                      onClick={() =>
                        setSeverity((prev) =>
                          active ? prev.filter((x) => x !== s) : [...prev, s],
                        )
                      }
                    />
                  )
                })}
              </div>
            </div>
          )}

          <div className="flex items-center gap-3">
            <Button
              type="submit"
              variant="primary"
              size="md"
              disabled={generating}
              isLoading={generating}
            >
              {generating ? "Generating…" : "Generate report"}
            </Button>
            {generateError && (
              <p role="alert" className="text-sm text-[var(--color-severity-critical-text)]">{generateError}</p>
            )}
          </div>
        </form>
      </div>

      <ScheduledReportsPanel />

      {deleteError && (
        <p className="text-sm text-[var(--color-severity-critical-text)]">{deleteError}</p>
      )}
      {reports.length === 0 ? (
        <ReportsEmptyState />
      ) : (
      <div className="space-y-3">
      <div className="flex items-baseline justify-between">
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">Report history</h2>
        <span className="text-xs text-[var(--color-text-secondary)] tabular-nums">
          {total} {total === 1 ? "report" : "reports"}
        </span>
      </div>
      <Card padding="none" className="overflow-auto">
        <Table className="min-w-full">
          <Thead>
            <Tr>
              <Th className="px-5">Title</Th>
              <Th className="px-5">Type</Th>
              <Th className="px-5">Status</Th>
              <Th className="px-5">Format</Th>
              <Th className="px-5 text-right">Rows</Th>
              <Th className="px-5 text-right">Size</Th>
              <Th className="px-5">Created</Th>
              <Th className="px-5">Actions</Th>
            </Tr>
          </Thead>
          <Tbody>
            {(
              reports.map(report => {
                return (
                  <Tr key={report.id}>
                    <Td className="px-5 py-3.5 max-w-xs truncate text-[var(--color-text-primary)]" title={report.title}>{report.title}</Td>
                    <Td className="px-5 py-3.5">
                      <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-semibold ${
                        TYPE_BADGE[report.report_type] ?? "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]"
                      }`}>
                        {reportTypeLabel(report.report_type)}
                      </span>
                    </Td>
                    <Td className="px-5 py-3.5">
                      {(() => {
                        const view = REPORT_STATUS[report.status] ?? { tone: "stale" as Status, label: report.status }
                        return (
                          <span title={report.error ?? undefined}>
                            <StatusPill status={view.tone} label={view.label} />
                          </span>
                        )
                      })()}
                    </Td>
                    <Td className="px-5 py-3.5 text-xs font-mono uppercase text-[var(--color-text-secondary)]">{report.format}</Td>
                    <Td className="px-5 py-3.5 text-right tabular-nums text-[var(--color-text-secondary)]">
                      {report.row_count ?? "—"}
                    </Td>
                    <Td className="px-5 py-3.5 text-right tabular-nums text-[var(--color-text-secondary)]">
                      {formatBytes(report.file_size_bytes)}
                    </Td>
                    <Td className="px-5 py-3.5 text-[var(--color-text-secondary)]">
                      {relativeTime(report.created_at)}
                    </Td>
                    <Td className="px-5 py-3.5">
                      <div className="flex items-center gap-1">
                        <a
                          href={
                            report.download_url && /^https?:\/\//i.test(report.download_url)
                              ? report.download_url
                              : undefined
                          }
                          download
                          target="_blank"
                          rel="noopener noreferrer"
                          aria-disabled={!report.download_url}
                          className={`inline-flex h-7 items-center rounded-md px-2.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-surface)] ${
                            report.download_url
                              ? "text-[var(--color-accent)] hover:bg-[var(--color-bg-hover)]"
                              : "pointer-events-none opacity-40 text-[var(--color-text-secondary)]"
                          }`}
                        >
                          Download
                        </a>
                        <Button
                          variant="ghost"
                          size="xs"
                          onClick={() => void handleDelete(report.id)}
                          disabled={deletingId === report.id}
                          isLoading={deletingId === report.id}
                          aria-label="Delete report"
                        >
                          Delete
                        </Button>
                      </div>
                    </Td>
                  </Tr>
                )
              })
            )}
          </Tbody>
        </Table>
      </Card>
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
        <p className="max-w-sm text-sm text-[var(--color-text-secondary)]">Generate your first report by picking a template or using the form above.</p>
      </div>
    </div>
  )
}
