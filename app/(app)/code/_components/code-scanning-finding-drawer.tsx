"use client"

import { useEffect, useState } from "react"
import { FindingsDrawerShell } from "@/components/shared/FindingsDrawerShell"
import type { CodeScanningFinding } from "@/lib/client/code-scanning-client"
import { firstSentence } from "@/lib/shared/code-scanning/drawer-helpers"
import { dismissCodeScanningFinding, reopenCodeScanningFinding } from "@/lib/client/code-scanning-client"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

import { sevBadgeClass as severityBadgeClass, stateBadgeClass } from "@/lib/shared/ui/badge-styles"
import { formatDate } from "@/lib/shared/utils"

function stateLabel(state: CodeScanningFinding["state"]): string {
  switch (state) {
    case "open":         return "Open"
    case "dismissed":    return "Dismissed"
    case "fixed":        return "Fixed"
    case "awaiting_fix": return "Awaiting Fix"
  }
}

function verdictChipClass(verdict: string): string {
  const v = verdict.toLowerCase()
  if (v.includes("false positive") || v.includes("not exploitable") || v.includes("benign") || v.includes("unlikely"))
    return "border border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
  if (v.includes("true positive") || v.includes("confirmed") || v.includes("exploitable") || v.includes("vulnerable"))
    return "border border-red-500/30 bg-red-500/10 text-red-400"
  if (v.includes("likely"))
    return "border border-amber-500/30 bg-amber-500/10 text-amber-400"
  return "border border-blue-500/30 bg-blue-500/10 text-blue-400"
}

type ReachabilityVerdict = "reachable" | "unreachable" | "unknown"

function reachabilityBadgeConfig(verdict: ReachabilityVerdict): {
  svgPath: string
  label: string
  cls: string
  ariaLabel: string
  title: string
} {
  switch (verdict) {
    case "reachable":
      return {
        svgPath: "M13 2 3 14h9l-1 8 10-12h-9l1-8z",
        label: "Reachable",
        cls: "bg-red-500/10 text-red-400 border border-red-500/20",
        ariaLabel: "Reachability: Reachable",
        title: "This finding is reachable from a detected entry point",
      }
    case "unreachable":
      return {
        svgPath: "M2 12a10 10 0 1 0 20 0 10 10 0 0 0-20 0M4.93 4.93l14.14 14.14",
        label: "Unreachable",
        cls: "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20",
        ariaLabel: "Reachability: Unreachable",
        title: "This code is not reachable from any detected entry point",
      }
    default:
      return {
        svgPath: "M12 2a10 10 0 1 0 0 20A10 10 0 0 0 12 2m0 6v4m0 4h.01",
        label: "Unknown",
        cls: "bg-[var(--color-border)]/40 text-[var(--color-text-secondary)]",
        ariaLabel: "Reachability: Unknown",
        title: "Reachability could not be determined — dynamic dispatch or missing entry points",
      }
  }
}

const DISMISS_REASONS = [
  "Fix started",
  "Risk is tolerable",
  "Alert is inaccurate",
  "Vulnerable code is not used",
]

// ---------------------------------------------------------------------------
// DetailItem — matches SCA pattern
// ---------------------------------------------------------------------------

function DetailItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-3">
      <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--color-text-secondary)]">
        {label}
      </p>
      <p className="mt-1 break-words text-sm font-medium text-[var(--color-text-primary)]">
        {value}
      </p>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface Props {
  finding: CodeScanningFinding | null
  org: string
  onClose: () => void
  onActionComplete: () => void
}

// ---------------------------------------------------------------------------
// CodeScanningFindingDrawer
// ---------------------------------------------------------------------------

export function CodeScanningFindingDrawer({ finding, org, onClose, onActionComplete }: Props) {
  const [dismissOpen, setDismissOpen] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  useEffect(() => {
    setDismissOpen(false)
    setActionError(null)
  }, [finding])

  // Escape key handling moved to FindingsDrawerShell

  async function handleDismiss(reason: string) {
    if (!finding) return
    setIsSubmitting(true)
    setActionError(null)
    try {
      const { ok, payload } = await dismissCodeScanningFinding(org, finding.identity_key, reason)
      if (!ok || payload.error) {
        setActionError(payload.error ?? "Failed to dismiss finding")
      } else {
        setDismissOpen(false)
        onActionComplete()
        onClose()
      }
    } catch {
      setActionError("Network error")
    } finally {
      setIsSubmitting(false)
    }
  }

  async function handleReopen() {
    if (!finding) return
    setIsSubmitting(true)
    setActionError(null)
    try {
      const { ok, payload } = await reopenCodeScanningFinding(org, finding.identity_key)
      if (!ok || payload.error) {
        setActionError(payload.error ?? "Failed to reopen finding")
      } else {
        onActionComplete()
        onClose()
      }
    } catch {
      setActionError("Network error")
    } finally {
      setIsSubmitting(false)
    }
  }

  const githubUrl = finding
    ? `https://github.com/${finding.repo_full_name}/blob/HEAD/${finding.file_path}#L${finding.start_line}`
    : null

  // Prefer code_window (±40 lines of context) over snippet (flagged lines only)
  const codeSource = finding?.code_window || finding?.snippet || ""
  const codeStartLine = finding?.code_window
    ? Math.max(1, finding.start_line - 40)
    : (finding?.start_line ?? 1)
  const snippetLines = codeSource
    ? codeSource.split("\n").map((content, i) => ({
        number: codeStartLine + i,
        content,
      }))
    : []

  return (
    <FindingsDrawerShell open={!!finding} onClose={onClose}>
      {/* Header */}
      <div className="flex items-start justify-between gap-4 border-b border-[var(--color-border)] p-5">
        <div className="min-w-0">
          <p className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">
            SAST Finding
          </p>
          {finding && (
            <>
              <h3
                className="mt-2 text-xl font-semibold text-[var(--color-text-primary)]"
              >
                {firstSentence(finding.message)}
              </h3>
              <p className="mt-1 truncate font-[family-name:var(--font-jetbrains-mono)] text-xs text-[var(--color-text-secondary)]">
                {finding.rule_id}
              </p>
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize ${severityBadgeClass(finding.severity)}`}>
                  {finding.severity}
                </span>
                <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${stateBadgeClass(finding.state)}`}>
                  {stateLabel(finding.state)}
                </span>
                {finding.reachability && (() => {
                  const cfg = reachabilityBadgeConfig(
                    finding.reachability.verdict as ReachabilityVerdict
                  )
                  return (
                    <span
                      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${cfg.cls}`}
                      aria-label={cfg.ariaLabel}
                      title={cfg.title}
                    >
                      <svg
                        width="10"
                        height="10"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        aria-hidden="true"
                      >
                        <path d={cfg.svgPath} />
                      </svg>
                      {cfg.label}
                    </span>
                  )
                })()}
              </div>
            </>
          )}
        </div>

        <div className="flex shrink-0 items-center gap-2">
          {finding && githubUrl && (
            <a
              href={githubUrl}
              target="_blank"
              rel="noreferrer"
              className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-accent)] hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-accent-hover)]"
            >
              View in repository
            </a>
          )}
          {finding && (
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)]"
            >
              ✕ Close
            </button>
          )}
        </div>
      </div>

      {/* Body */}
      {finding && (
        <div className="space-y-6 p-5">

          {/* ── 1. Code Context ─────────────────────────────────────────── */}
          {snippetLines.length > 0 && (
            <section>
              <p className="mb-2 text-xs font-semibold uppercase tracking-[0.18em] text-[var(--color-text-secondary)]">
                {finding.code_window ? "Code Context" : "Code Snippet"}
              </p>
              {/* Metadata bar: repo · file path + line range */}
              <div className="mb-1 flex items-center justify-between gap-2 rounded-t-2xl border border-b-0 border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-1.5 text-xs text-[var(--color-text-secondary)]">
                <span className="flex min-w-0 items-center gap-1.5 overflow-hidden">
                  <span className="shrink-0">{finding.repo_full_name}</span>
                  <span className="shrink-0 opacity-40">·</span>
                  <span
                    className="min-w-0 truncate font-[family-name:var(--font-jetbrains-mono)]"
                    title={finding.file_path}
                  >
                    {finding.file_path}
                  </span>
                </span>
                <span className="shrink-0">
                  {finding.code_window
                    ? `Lines ${codeStartLine}–${codeStartLine + snippetLines.length - 1}`
                    : `Lines ${finding.start_line}–${finding.end_line}`}
                </span>
              </div>
              <div className="max-h-[620px] overflow-auto rounded-b-2xl border border-[var(--color-border)] bg-slate-100 dark:bg-slate-950">
                <pre className="min-w-max p-4 text-sm leading-6 text-slate-700 dark:text-slate-300">
                  <code>
                    {snippetLines.map((line) => {
                      const isHighlighted = line.number >= finding.start_line && line.number <= finding.end_line
                      return (
                        <span
                          key={line.number}
                          className={`block ${isHighlighted ? "-mx-4 bg-orange-500/15 px-4 text-orange-700 dark:text-orange-100" : ""}`}
                        >
                          <span className="mr-5 inline-block w-12 select-none text-right font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-secondary)]">
                            {line.number}
                          </span>
                          <span>{line.content || " "}</span>
                        </span>
                      )
                    })}
                  </code>
                </pre>
              </div>
            </section>
          )}

          {/* ── 2. Description ───────────────────────────────────────────── */}
          <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
            <p className="mb-2 text-xs font-semibold uppercase tracking-[0.18em] text-[var(--color-text-secondary)]">
              Description
            </p>
            <p className="text-sm leading-relaxed text-[var(--color-text-primary)]">
              {finding.message}
            </p>
          </div>

          {/* ── 3. Data Flow ─────────────────────────────────────────────── */}
          <section className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
            <p className="mb-3 text-xs font-semibold uppercase tracking-[0.18em] text-[var(--color-text-secondary)]">
              Data Flow
            </p>
            {finding.code_flows && finding.code_flows.length > 0 ? (
              <div className="space-y-0">
                {finding.code_flows.map((step, idx) => (
                  <div key={idx} className="flex gap-3">
                    <div className="flex flex-col items-center">
                      <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-[var(--color-accent)]/10 text-[10px] font-bold tabular-nums text-[var(--color-accent)]">
                        {idx + 1}
                      </span>
                      {idx < finding.code_flows!.length - 1 && (
                        <div className="my-0.5 w-px flex-1 bg-[var(--color-border)]" />
                      )}
                    </div>
                    <div className="min-w-0 pb-3">
                      <p className="flex items-baseline gap-1.5">
                        <span
                          className="min-w-0 truncate font-[family-name:var(--font-jetbrains-mono)] text-xs text-[var(--color-text-primary)]"
                          title={step.file}
                        >
                          {step.file.split("/").pop()}
                        </span>
                        <span className="shrink-0 text-[11px] text-[var(--color-text-secondary)]">
                          :{step.line}
                        </span>
                      </p>
                      {step.snippet && (
                        <p className="mt-0.5 truncate font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-secondary)]">
                          {step.snippet.trim()}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-[var(--color-text-secondary)]">No data flow traced for this finding.</p>
            )}
          </section>

          {/* ── 4. Reachability ──────────────────────────────────────────── */}
          <section className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
            <p className="mb-3 text-xs font-semibold uppercase tracking-[0.18em] text-[var(--color-text-secondary)]">
              Reachability
            </p>

            {finding.reachability?.verdict === "reachable" && finding.reachability.call_chain && finding.reachability.call_chain.length > 0 ? (
              <div className="space-y-0">
                {/* Entry point — step 0 */}
                <div className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-[var(--color-accent)]/10">
                      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                        <path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z" />
                      </svg>
                    </span>
                    <div className="my-0.5 w-px flex-1 bg-[var(--color-border)]" />
                  </div>
                  <div className="min-w-0 pb-3">
                    <p className="text-xs font-semibold text-[var(--color-accent)]">
                      {finding.reachability.entry_point ?? "Entry point"}
                    </p>
                  </div>
                </div>

                {/* Intermediate steps */}
                {finding.reachability.call_chain.map((step, idx) => {
                  const isLast = idx === finding.reachability!.call_chain!.length - 1
                  return (
                    <div key={idx} className="flex gap-3">
                      <div className="flex flex-col items-center">
                        <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-[var(--color-accent)]/10 text-[10px] font-bold tabular-nums text-[var(--color-accent)]">
                          {idx + 1}
                        </span>
                        {!isLast && <div className="my-0.5 w-px flex-1 bg-[var(--color-border)]" />}
                      </div>
                      <div className={`min-w-0 pb-3 ${isLast ? "border-l-2 border-[var(--color-accent)] pl-2" : ""}`}>
                        <p className="flex items-baseline gap-1.5">
                          <span className="font-medium text-sm text-[var(--color-text-primary)]">
                            {step.function}
                          </span>
                        </p>
                        <p className="flex items-baseline gap-1">
                          <span
                            className="min-w-0 truncate font-[family-name:var(--font-jetbrains-mono)] text-xs text-[var(--color-text-secondary)]"
                            title={step.file}
                          >
                            {step.file.split("/").pop()}
                          </span>
                          <span className="shrink-0 text-[11px] text-[var(--color-text-secondary)]">
                            :{step.line}
                          </span>
                        </p>
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : finding.reachability?.verdict === "unreachable" ? (
              <p className="text-sm text-[var(--color-text-secondary)]">
                This code is not reachable from any detected entry point.
              </p>
            ) : (
              <p className="text-sm text-[var(--color-text-secondary)]">
                Reachability could not be determined for this finding.
              </p>
            )}
          </section>

          {/* ── 5. AI Analysis + Fix Suggestion ─────────────────────────── */}
          <section className="overflow-hidden rounded-2xl border border-[var(--color-border)]">
              <div className="flex items-center gap-2.5 border-b border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3">
                <svg
                  className="h-4 w-4 shrink-0 text-[var(--color-text-secondary)]"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                >
                  <path d="M12 3v1m0 16v1M4.22 4.22l.7.7m13.16 13.16.7.7M3 12h1m16 0h1M4.22 19.78l.7-.7M18.36 5.64l.7-.7" />
                  <circle cx="12" cy="12" r="4" />
                </svg>
                <span className="text-xs font-semibold uppercase tracking-widest text-[var(--color-text-secondary)]">
                  AI Analysis
                </span>
                {finding.ai_review && finding.ai_review.verdict !== "skipped" && (
                  <div className="ml-auto flex items-center gap-2">
                    {finding.ai_review.confidence && (
                      <span className="text-[11px] font-medium text-[var(--color-text-secondary)] capitalize">
                        {finding.ai_review.confidence} confidence
                      </span>
                    )}
                    <span className={`max-w-[55%] truncate rounded-full px-2.5 py-0.5 text-xs font-semibold ${verdictChipClass(finding.ai_review.verdict)}`}>
                      {finding.ai_review.verdict}
                    </span>
                  </div>
                )}
              </div>

              {finding.ai_review && (
                <div className="bg-[var(--color-surface)] px-4 py-4 space-y-3">
                  {finding.ai_review.reasoning && (
                    <div>
                      <p className="mb-1 text-[11px] font-semibold uppercase tracking-widest text-[var(--color-text-secondary)]">
                        Reasoning
                      </p>
                      <p className="text-xs leading-relaxed text-[var(--color-text-secondary)] whitespace-pre-wrap">
                        {finding.ai_review.reasoning}
                      </p>
                    </div>
                  )}
                  <div>
                    <p className="mb-1 text-[11px] font-semibold uppercase tracking-widest text-[var(--color-text-secondary)]">
                      Explanation
                    </p>
                    <p className="text-sm leading-relaxed text-[var(--color-text-primary)]">
                      {finding.ai_review.explanation}
                    </p>
                  </div>
                </div>
              )}

              {finding.fix_suggestion && (
                <div className={`${finding.ai_review ? "border-t border-[var(--color-border)]" : ""} bg-[var(--color-surface)] px-4 py-4`}>
                  <p className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-[var(--color-text-secondary)]">
                    Recommended fix
                  </p>
                  <p className="text-sm leading-relaxed text-[var(--color-text-primary)]">
                    {finding.fix_suggestion}
                  </p>
                </div>
              )}
            {!finding.ai_review && !finding.fix_suggestion && (
              <div className="bg-[var(--color-surface)] px-4 py-4">
                <p className="text-sm text-[var(--color-text-secondary)]">No AI analysis available for this finding.</p>
              </div>
            )}
          </section>

          {/* ── 6. Details ───────────────────────────────────────────────── */}
          <section className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
            <p className="mb-3 text-xs font-semibold uppercase tracking-[0.18em] text-[var(--color-text-secondary)]">
              Details
            </p>
            <div className="grid gap-3 sm:grid-cols-2">
              <DetailItem label="Category" value={finding.category} />
              <DetailItem label="Confidence" value={finding.confidence} />
              {finding.language && <DetailItem label="Language" value={finding.language} />}
              {finding.cwe.length > 0 && <DetailItem label="CWE" value={finding.cwe.join(", ")} />}
              <DetailItem label="First Seen" value={formatDate(finding.first_seen_at)} />
              {finding.fixed_at && <DetailItem label="Fixed At" value={formatDate(finding.fixed_at)} />}
              {finding.dismissed_at && <DetailItem label="Dismissed At" value={formatDate(finding.dismissed_at)} />}
              {finding.dismissed_by && <DetailItem label="Dismissed By" value={finding.dismissed_by} />}
              {finding.dismissed_reason && <DetailItem label="Dismiss Reason" value={finding.dismissed_reason} />}
            </div>
          </section>

        </div>
      )}

      {/* Footer actions */}
      {finding && (
        <div className="border-t border-[var(--color-border)] p-5">
          {actionError && <p className="mb-3 text-xs text-red-500">{actionError}</p>}

          {finding.state === "dismissed" && (
            <div className="flex items-center justify-between rounded-2xl border border-purple-500/20 bg-purple-500/8 p-4">
              <div>
                <p className="text-sm font-medium text-purple-400">Dismissed</p>
                {finding.dismissed_reason && (
                  <p className="mt-0.5 text-xs text-purple-400/70">
                    Reason: {finding.dismissed_reason}
                  </p>
                )}
              </div>
              <button
                type="button"
                onClick={() => void handleReopen()}
                disabled={isSubmitting}
                className="rounded-lg border border-purple-500/30 bg-[var(--color-surface-raised)] px-3 py-1.5 text-xs font-semibold text-purple-400 hover:bg-[var(--color-surface)] disabled:opacity-50"
              >
                Reopen
              </button>
            </div>
          )}

          {(finding.state === "open" || finding.state === "awaiting_fix") && (
            <div className="relative">
              <button
                type="button"
                onClick={() => setDismissOpen(!dismissOpen)}
                disabled={isSubmitting}
                className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] disabled:opacity-50"
              >
                Dismiss finding
              </button>
              {dismissOpen && (
                <div className="absolute left-0 top-full z-10 mt-1 w-64 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-2 shadow-lg">
                  <p className="px-2 py-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
                    Select reason
                  </p>
                  {DISMISS_REASONS.map((reason) => (
                    <button
                      key={reason}
                      type="button"
                      onClick={() => void handleDismiss(reason)}
                      disabled={isSubmitting}
                      className="w-full rounded-lg px-2 py-1.5 text-left text-sm text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)] disabled:opacity-50"
                    >
                      {reason}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* fixed state: no actions */}
        </div>
      )}
    </FindingsDrawerShell>
  )
}
