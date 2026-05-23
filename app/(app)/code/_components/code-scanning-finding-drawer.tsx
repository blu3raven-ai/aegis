"use client"

import { useEffect, useMemo, useState } from "react"
import { FindingsDrawerShell } from "@/components/shared/FindingsDrawerShell"
import {
  DrawerHeader,
  DrawerStatusBanner,
  DrawerSection,
  DrawerCodeBlock,
  DrawerDetailGrid,
  DrawerFooter,
  DismissPopover,
} from "@/components/shared/FindingDrawer"
import type { CodeScanningFinding } from "@/lib/client/code-scanning-client"
import { firstSentence } from "@/lib/shared/code-scanning/drawer-helpers"
import {
  dismissCodeScanningFinding,
  reopenCodeScanningFinding,
} from "@/lib/client/code-scanning-client"
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

const CWE_LABELS: Record<string, string> = {
  "CWE-22":  "Path traversal",
  "CWE-78":  "OS command injection",
  "CWE-79":  "Cross-site scripting (XSS)",
  "CWE-89":  "SQL injection",
  "CWE-94":  "Code injection",
  "CWE-190": "Integer overflow or wraparound",
  "CWE-287": "Improper authentication",
  "CWE-312": "Cleartext storage of sensitive data",
  "CWE-319": "Cleartext transmission of sensitive data",
  "CWE-327": "Use of weak cryptographic algorithm",
  "CWE-476": "Null pointer dereference",
  "CWE-502": "Deserialization of untrusted data",
  "CWE-601": "Open redirect",
  "CWE-611": "XML external entity (XXE)",
  "CWE-918": "Server-side request forgery (SSRF)",
}

function verdictChipClass(verdict: string): string {
  const v = verdict.toLowerCase()
  if (v.includes("false positive") || v.includes("not exploitable") || v.includes("benign") || v.includes("unlikely"))
    return "border border-[var(--color-verdict-safe-border)] bg-[var(--color-verdict-safe-subtle)] text-[var(--color-verdict-safe)]"
  if (v.includes("true positive") || v.includes("confirmed") || v.includes("exploitable") || v.includes("vulnerable"))
    return "border border-[var(--color-verdict-risk-border)] bg-[var(--color-verdict-risk-subtle)] text-[var(--color-verdict-risk)]"
  if (v.includes("likely"))
    return "border border-[var(--color-verdict-uncertain-border)] bg-[var(--color-verdict-uncertain-subtle)] text-[var(--color-verdict-uncertain)]"
  return "border border-[var(--color-verdict-neutral-border)] bg-[var(--color-verdict-neutral-subtle)] text-[var(--color-verdict-neutral)]"
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
        cls: "bg-[var(--color-verdict-risk-subtle)] text-[var(--color-verdict-risk)] border border-[var(--color-verdict-risk-border)]",
        ariaLabel: "Reachability: Reachable",
        title: "This finding is reachable from a detected entry point",
      }
    case "unreachable":
      return {
        svgPath: "M2 12a10 10 0 1 0 20 0 10 10 0 0 0-20 0M4.93 4.93l14.14 14.14",
        label: "Unreachable",
        cls: "bg-[var(--color-verdict-safe-subtle)] text-[var(--color-verdict-safe)] border border-[var(--color-verdict-safe-border)]",
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

interface Props {
  finding: CodeScanningFinding | null
  org: string
  onClose: () => void
  onActionComplete: () => void
}

export function CodeScanningFindingDrawer({ finding, org, onClose, onActionComplete }: Props) {
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  useEffect(() => {
    setActionError(null)
  }, [finding])

  async function handleDismiss(reason: string) {
    if (!finding) return
    setIsSubmitting(true)
    setActionError(null)
    try {
      const { ok, payload } = await dismissCodeScanningFinding(org, finding.identity_key, reason)
      if (!ok || payload.error) {
        setActionError(payload.error ?? "Failed to dismiss finding")
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

  const codeSource = useMemo(
    () => finding?.code_window || finding?.snippet || "",
    [finding]
  )
  const codeStartLine = useMemo(
    () => finding?.code_window ? Math.max(1, finding.start_line - 40) : (finding?.start_line ?? 1),
    [finding]
  )
  const snippetLines = useMemo(
    () => codeSource
      ? codeSource.split("\n").map((content, i) => ({ number: codeStartLine + i, content }))
      : [],
    [codeSource, codeStartLine]
  )
  const detailItems = useMemo(
    () => finding ? [
      { label: "Category", value: finding.category },
      { label: "Confidence", value: finding.confidence },
      ...(finding.language ? [{ label: "Language", value: finding.language }] : []),
      ...(finding.cwe.length > 0 ? [{ label: "CWE", value: finding.cwe.join(", ") }] : []),
      { label: "First Seen", value: formatDate(finding.first_seen_at) },
      ...(finding.fixed_at ? [{ label: "Fixed At", value: formatDate(finding.fixed_at) }] : []),
      ...(finding.dismissed_at ? [{ label: "Dismissed At", value: formatDate(finding.dismissed_at) }] : []),
      ...(finding.dismissed_by ? [{ label: "Dismissed By", value: finding.dismissed_by }] : []),
      ...(finding.dismissed_reason ? [{ label: "Dismiss Reason", value: finding.dismissed_reason }] : []),
    ] : [],
    [finding]
  )

  return (
    <FindingsDrawerShell open={!!finding} onClose={onClose} label="SAST finding details">
      <DrawerHeader
        eyebrow="SAST Finding"
        title={finding ? firstSentence(finding.message) : ""}
        titleTooltip={finding?.message}
        identifier={finding?.rule_id}
        repoUrl={githubUrl ?? undefined}
        onClose={onClose}
        badges={finding ? (
          <>
            <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize ${severityBadgeClass(finding.severity)}`}>
              {finding.severity}
            </span>
            <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${stateBadgeClass(finding.state)}`}>
              {stateLabel(finding.state)}
            </span>
            {finding.reachability && (() => {
              const cfg = reachabilityBadgeConfig(finding.reachability.verdict as ReachabilityVerdict)
              return (
                <span
                  className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${cfg.cls}`}
                  aria-label={cfg.ariaLabel}
                  title={cfg.title}
                >
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <path d={cfg.svgPath} />
                  </svg>
                  {cfg.label}
                </span>
              )
            })()}
            {finding.cwe && finding.cwe.length > 0 && finding.cwe.map((id) => (
              <a
                key={id}
                href={`https://cwe.mitre.org/data/definitions/${id.replace(/^CWE-/i, "")}.html`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center rounded-full border border-[var(--color-border)] px-2 py-0.5 text-xs font-medium text-[var(--color-text-secondary)] hover:border-[var(--color-accent)]/40 hover:text-[var(--color-accent)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
                title={`View ${id} on MITRE CWE (opens in new tab)`}
              >
                {id}
                <span className="sr-only"> (opens in new tab)</span>
              </a>
            ))}
          </>
        ) : undefined}
      />

      <DrawerStatusBanner
        state={finding?.state ?? "open"}
        dismissedReason={finding?.dismissed_reason}
        fixedAt={finding?.fixed_at ? formatDate(finding.fixed_at) : undefined}
        onReopen={() => void handleReopen()}
      />

      {finding && (
        <div className="flex-1 overflow-y-auto p-5 space-y-5">

          {/* ── 1. Code Context ── */}
          {snippetLines.length > 0 && (
            <DrawerCodeBlock
              lines={snippetLines}
              highlightRange={{ start: finding.start_line, end: finding.end_line }}
              label={finding.repo_full_name}
              filePath={finding.file_path}
              lineRange={finding.code_window
                ? `Lines ${codeStartLine}–${codeStartLine + snippetLines.length - 1}`
                : `Lines ${finding.start_line}–${finding.end_line}`}
            />
          )}

          {/* ── Location — only when code block is absent ── */}
          {snippetLines.length === 0 && (
            <div className="rounded-lg bg-[var(--color-surface-raised)] px-3 py-2 text-xs text-[var(--color-text-secondary)]">
              <span className="font-semibold">Repository</span>{" "}
              <span className="text-[var(--color-text-primary)]">{finding.repo_full_name}</span>
            </div>
          )}

          {/* ── 2. AI Analysis + Fix Suggestion (promoted) ── */}
          <DrawerSection label="AI Analysis">
            {finding.ai_review && finding.ai_review.verdict !== "skipped" && (
              <div className="flex items-center gap-2.5 pb-3">
                <svg className="h-4 w-4 shrink-0 text-[var(--color-text-secondary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M12 3v1m0 16v1M4.22 4.22l.7.7m13.16 13.16.7.7M3 12h1m16 0h1M4.22 19.78l.7-.7M18.36 5.64l.7-.7" />
                  <circle cx="12" cy="12" r="4" />
                </svg>
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
              </div>
            )}

            {finding.ai_review ? (
              <div className="space-y-3">
                {finding.ai_review.reasoning && (
                  <div>
                    <p className="mb-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)]">Reasoning</p>
                    <p className="text-xs leading-relaxed text-[var(--color-text-secondary)] whitespace-pre-wrap">
                      {finding.ai_review.reasoning}
                    </p>
                  </div>
                )}
                <div>
                  <p className="mb-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)]">Explanation</p>
                  <p className="text-sm leading-relaxed text-[var(--color-text-primary)]">
                    {finding.ai_review.explanation}
                  </p>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                {/* CWE reference cards */}
                {finding.cwe && finding.cwe.length > 0 && (
                  <div className="space-y-2">
                    {finding.cwe.map((id) => {
                      const normalised = id.toUpperCase().startsWith("CWE-") ? id.toUpperCase() : `CWE-${id}`
                      const label = CWE_LABELS[normalised]
                      const num = normalised.replace(/^CWE-/, "")
                      return (
                        <a
                          key={id}
                          href={`https://cwe.mitre.org/data/definitions/${num}.html`}
                          target="_blank"
                          rel="noreferrer"
                          className="flex items-center justify-between gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2.5 transition-colors hover:border-[var(--color-accent)]/40 hover:bg-[var(--color-accent)]/5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
                        >
                          <div className="min-w-0">
                            <p className="text-xs font-semibold text-[var(--color-text-primary)]">{normalised}</p>
                            {label && <p className="mt-0.5 text-[11px] text-[var(--color-text-secondary)]">{label}</p>}
                          </div>
                          <span className="shrink-0 text-[11px] text-[var(--color-accent)]">MITRE →<span className="sr-only"> (opens in new tab)</span></span>
                        </a>
                      )
                    })}
                  </div>
                )}

                {/* Category */}
                {finding.category && (
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)]">Category</span>
                    <span className="rounded-full border border-[var(--color-border)] px-2 py-0.5 text-[11px] text-[var(--color-text-secondary)]">{finding.category}</span>
                  </div>
                )}

                {/* Manual triage checklist */}
                <div>
                  <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)]">Manual triage</p>
                  <ul className="space-y-1.5">
                    {[
                      "Does attacker-controlled data reach this code path?",
                      "Is there input validation or sanitization before this point?",
                      "Does the call chain cross a trust boundary?",
                      "What is the worst-case impact if this is exploited?",
                    ].map((q) => (
                      <li key={q} className="flex items-start gap-2 text-xs text-[var(--color-text-secondary)]">
                        <span className="mt-0.5 shrink-0 text-[var(--color-border)]">—</span>
                        {q}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}

            {finding.fix_suggestion && (
              <div className="mt-3 border-t border-[var(--color-border)] pt-3">
                <p className="mb-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)]">Recommended fix</p>
                <p className="text-sm leading-relaxed text-[var(--color-text-primary)]">
                  {finding.fix_suggestion}
                </p>
              </div>
            )}
          </DrawerSection>

          {/* ── Description ── */}
          <DrawerSection label="Description">
            <p className="text-sm leading-relaxed text-[var(--color-text-primary)]">
              {finding.message}
            </p>
          </DrawerSection>

          {/* ── 3. Data Flow ── */}
          <DrawerSection label="Data Flow">
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
                        <span className="min-w-0 truncate font-[family-name:var(--font-jetbrains-mono)] text-xs text-[var(--color-text-primary)]" title={step.file}>
                          {step.file.split("/").pop()}
                        </span>
                        <span className="shrink-0 text-[11px] text-[var(--color-text-secondary)]">:{step.line}</span>
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
          </DrawerSection>

          {/* ── 4. Reachability ── */}
          <DrawerSection label="Reachability">
            {finding.reachability?.verdict === "reachable" ? (() => {
              const chain = finding.reachability.call_chain ?? []
              const findingUrl = `https://github.com/${finding.repo_full_name}/blob/HEAD/${finding.file_path}#L${finding.start_line}`
              const Arrow = () => (
                <div className="flex flex-col items-center py-0.5" aria-hidden="true">
                  <div className="h-3 w-px bg-[var(--color-border)]" />
                  <svg width="8" height="5" viewBox="0 0 8 5" fill="none">
                    <path d="M0 0 L4 5 L8 0" stroke="var(--color-border)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </div>
              )
              const LinkIcon = () => (
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                  <polyline points="15 3 21 3 21 9" />
                  <line x1="10" y1="14" x2="21" y2="3" />
                </svg>
              )
              return (
                <div className="flex flex-col items-stretch">
                  {/* Call chain: call_chain[0] IS the entry point — mark it, don't show a separate entry node */}
                  {chain.length > 0 ? chain.map((step, idx) => {
                    const isEntry = idx === 0
                    const stepUrl = `https://github.com/${finding.repo_full_name}/blob/HEAD/${step.file}#L${step.line}`
                    return (
                      <div key={idx} className="flex flex-col items-stretch">
                        {idx > 0 && <Arrow />}
                        <div className={`rounded-lg border px-3 py-2.5 ${isEntry ? "border-[var(--color-accent)]/30 bg-[var(--color-accent)]/5" : "border-[var(--color-border)] bg-[var(--color-surface-raised)]"}`}>
                          <div className="flex items-center gap-2">
                            {isEntry && (
                              <svg className="h-3.5 w-3.5 shrink-0 text-[var(--color-accent)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                                <path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z" />
                              </svg>
                            )}
                            <p className={`font-[family-name:var(--font-jetbrains-mono)] text-xs font-semibold ${isEntry ? "text-[var(--color-accent)]" : "text-[var(--color-text-primary)]"}`}>
                              {step.function}
                            </p>
                            <div className="ml-auto flex shrink-0 items-center gap-1.5">
                              {isEntry && (
                                <span className="rounded-full bg-[var(--color-accent)]/10 px-1.5 py-0.5 text-[10px] font-medium text-[var(--color-accent)]">entry</span>
                              )}
                              <a href={stepUrl} target="_blank" rel="noreferrer" className="text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]" aria-label={`View ${step.file}:${step.line} on GitHub (opens in new tab)`} title={`${step.file}:${step.line}`}>
                                <LinkIcon />
                                <span className="sr-only">(opens in new tab)</span>
                              </a>
                            </div>
                          </div>
                          <p className="mt-1 font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-secondary)]" title={step.file}>
                            {step.file}<span className="text-[var(--color-text-primary)]">:{step.line}</span>
                          </p>
                        </div>
                      </div>
                    )
                  }) : (
                    /* No call chain (module-level or missing) — show entry_point label only */
                    <div className="rounded-lg border border-[var(--color-accent)]/30 bg-[var(--color-accent)]/5 px-3 py-2.5">
                      <div className="flex items-center gap-2">
                        <svg className="h-3.5 w-3.5 shrink-0 text-[var(--color-accent)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                          <path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z" />
                        </svg>
                        <span className="font-[family-name:var(--font-jetbrains-mono)] text-xs font-semibold text-[var(--color-accent)]">
                          {finding.reachability.entry_point ?? "Entry point"}
                        </span>
                        <span className="ml-auto rounded-full bg-[var(--color-accent)]/10 px-1.5 py-0.5 text-[10px] font-medium text-[var(--color-accent)]">entry</span>
                      </div>
                      {finding.reachability.entry_point === "module-level" && (
                        <p className="mt-1 text-[11px] text-[var(--color-text-secondary)]">Executes at module level on import</p>
                      )}
                    </div>
                  )}

                  {/* Terminal: always show the finding's exact vulnerable line as the sink */}
                  <Arrow />
                  <div className="rounded-lg border border-[var(--color-verdict-risk-border)] bg-[var(--color-verdict-risk-subtle)] px-3 py-2.5">
                    <div className="flex items-center gap-2">
                      <p className="font-[family-name:var(--font-jetbrains-mono)] text-xs font-semibold text-[var(--color-text-primary)]" title={finding.file_path}>
                        {finding.file_path}<span className="text-[var(--color-verdict-risk)]">:{finding.start_line}</span>
                      </p>
                      <div className="ml-auto flex shrink-0 items-center gap-1.5">
                        <span className="rounded-full border border-[var(--color-verdict-risk-border)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--color-verdict-risk)]">sink</span>
                        <a href={findingUrl} target="_blank" rel="noreferrer" className="text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]" aria-label={`View ${finding.file_path}:${finding.start_line} on GitHub (opens in new tab)`} title={`${finding.file_path}:${finding.start_line}`}>
                          <LinkIcon />
                          <span className="sr-only">(opens in new tab)</span>
                        </a>
                      </div>
                    </div>
                  </div>
                </div>
              )
            })() : finding.reachability?.verdict === "unreachable" ? (
              <p className="text-sm text-[var(--color-text-secondary)]">This code is not reachable from any detected entry point.</p>
            ) : (
              <p className="text-sm text-[var(--color-text-secondary)]">Reachability could not be determined for this finding.</p>
            )}
          </DrawerSection>

          {/* ── 5. Details ── */}
          <DrawerSection label="Details">
            <DrawerDetailGrid items={detailItems} />
          </DrawerSection>

        </div>
      )}

      <DrawerFooter>
        {actionError && <p className="mb-3 text-xs text-red-500">{actionError}</p>}
        {(finding?.state === "open" || finding?.state === "awaiting_fix") && (
          <DismissPopover
            reasons={DISMISS_REASONS}
            onDismiss={(reason) => void handleDismiss(reason)}
            isLoading={isSubmitting}
          />
        )}
      </DrawerFooter>
    </FindingsDrawerShell>
  )
}
