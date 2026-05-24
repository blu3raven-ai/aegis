"use client"

import { useEffect, useMemo, useRef, useState } from "react"
import { FindingsDrawerShell } from "@/components/shared/FindingsDrawerShell"
import {
  DrawerHeader,
  DrawerStatusBanner,
  DrawerSection,
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

function CodeLines({
  code,
  startLine,
  highlightIdx,
  borderCls,
  hlRowCls,
}: {
  code: string
  startLine: number
  highlightIdx: number
  borderCls: string
  hlRowCls: string
}) {
  const rows = code.trimEnd().split("\n")
  const hlRef = useRef<HTMLTableRowElement>(null)

  useEffect(() => {
    hlRef.current?.scrollIntoView({ block: "center" })
  }, [code, highlightIdx])

  return (
    <div className={`border-t ${borderCls} overflow-hidden`}>
      <div className="overflow-x-auto max-h-48 overflow-y-auto">
        <table className="w-full border-collapse">
          <tbody>
            {rows.map((row, i) => (
              <tr key={i} ref={i === highlightIdx ? hlRef : undefined} className={i === highlightIdx ? hlRowCls : ""}>
                <td className="select-none w-9 text-right pr-3 pl-2 font-[family-name:var(--font-jetbrains-mono)] text-[10px] text-[var(--color-text-secondary)]/35 leading-relaxed align-top py-[1px] whitespace-nowrap">
                  {startLine + i}
                </td>
                <td className="pr-3 align-top py-[1px]">
                  <pre className="font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-secondary)] whitespace-pre leading-relaxed">
                    {row || " "}
                  </pre>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function CweCard({ id }: { id: string }) {
  const normalised = id.toUpperCase().startsWith("CWE-") ? id.toUpperCase() : `CWE-${id}`
  const num = normalised.replace(/^CWE-/, "")
  const [name, setName] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    fetch(`/api/cwe/${num}`)
      .then((r) => r.json())
      .then((data: { name: string | null }) => { if (!cancelled) setName(data.name ?? null) })
      .catch(() => {})
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [num])

  return (
    <a
      href={`https://cwe.mitre.org/data/definitions/${num}.html`}
      target="_blank"
      rel="noreferrer"
      className="flex items-center justify-between gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2.5 transition-colors hover:border-[var(--color-accent)]/40 hover:bg-[var(--color-accent)]/5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
    >
      <div className="min-w-0">
        <p className="text-xs font-semibold text-[var(--color-text-primary)]">{normalised}</p>
        {loading ? (
          <div className="mt-0.5 h-3 w-32 animate-pulse rounded bg-[var(--color-border)]" />
        ) : name ? (
          <p className="mt-0.5 text-[11px] text-[var(--color-text-secondary)]">{name}</p>
        ) : null}
      </div>
      <span className="shrink-0 text-[11px] text-[var(--color-accent)]">
        MITRE →<span className="sr-only"> (opens in new tab)</span>
      </span>
    </a>
  )
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
  const [remediationTab, setRemediationTab] = useState<"code" | "ai">("code")

  useEffect(() => {
    setActionError(null)
    setRemediationTab("code")
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

  const briefDetails = useMemo(
    () => finding ? [
      ...(finding.category ? [{ label: "Category", value: finding.category }] : []),
      ...(finding.language ? [{ label: "Language", value: finding.language }] : []),
      ...(finding.confidence ? [{ label: "Confidence", value: finding.confidence }] : []),
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
      />

      <DrawerStatusBanner
        state={finding?.state ?? "open"}
        dismissedReason={finding?.dismissed_reason}
        fixedAt={finding?.fixed_at ? formatDate(finding.fixed_at) : undefined}
        onReopen={() => void handleReopen()}
      />

      {finding && (
        <div className="flex-1 overflow-y-auto p-5 space-y-5">

          {/* ── 1. Security Brief ── */}
          <DrawerSection label="Security Brief">
            {/* Badge row — severity, state, reachability */}
            <div className="mb-3 flex flex-wrap items-center gap-1.5">
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
            </div>
            <p className="mb-4 text-sm leading-relaxed text-[var(--color-text-primary)]">
              {finding.message}
            </p>
            <DrawerDetailGrid items={briefDetails} />
          </DrawerSection>

          {/* ── 2. Remediation ── */}
          <DrawerSection label="Remediation">
            {/* Tab bar */}
            <div className="flex border-b border-[var(--color-border)] -mx-1 mb-4" role="tablist">
              {(["code", "ai"] as const).map((tab) => (
                <button
                  key={tab}
                  role="tab"
                  aria-selected={remediationTab === tab}
                  onClick={() => setRemediationTab(tab)}
                  className={`px-3 py-1.5 text-xs font-medium -mb-px border-b-2 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] ${
                    remediationTab === tab
                      ? "border-[var(--color-accent)] text-[var(--color-accent)]"
                      : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                  }`}
                >
                  {tab === "code" ? "Code & Reachability" : "AI Analysis"}
                </button>
              ))}
            </div>

            {/* Code & Reachability tab */}
            {remediationTab === "code" && (() => {
              const findingUrl = `https://github.com/${finding.repo_full_name}/blob/HEAD/${finding.file_path}#L${finding.start_line}`
              const snippetTrimmed = (finding.snippet || "").trim()
              // Prefer code_window (±40 lines of context). Fall back to snippet alone.
              // Find the highlighted row by matching the snippet text — this is robust
              // against off-by-one errors when code_window and start_line are misaligned.
              let vulnerableCode: string
              let codeWindowStart: number
              let codeHighlightIdx: number
              const rawWindow = (finding.code_window || "").trimEnd()
              if (rawWindow) {
                const windowLines = rawWindow.split("\n")
                const foundIdx = snippetTrimmed
                  ? windowLines.findIndex((l) => l.trim() === snippetTrimmed)
                  : -1
                if (foundIdx >= 0) {
                  // Snippet found — derive true start line from finding position
                  codeHighlightIdx = foundIdx
                  codeWindowStart = finding.start_line - foundIdx
                  vulnerableCode = rawWindow
                } else {
                  // Snippet not found (whitespace mismatch, etc.) — use math as fallback
                  codeWindowStart = Math.max(1, finding.start_line - 40)
                  codeHighlightIdx = finding.start_line - codeWindowStart
                  vulnerableCode = rawWindow
                }
              } else {
                // No code_window at all — show snippet as a single highlighted line
                vulnerableCode = snippetTrimmed
                codeWindowStart = finding.start_line
                codeHighlightIdx = 0
              }
              const verdict = finding.reachability?.verdict

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
                <div className="space-y-4">

                  {/* Vulnerable code — always shown regardless of reachability */}
                  <div className="rounded-lg border border-[var(--color-border)] bg-slate-100 dark:bg-slate-950 overflow-hidden">
                    <div className="flex items-center gap-2 border-b border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-1.5">
                      <p className="min-w-0 truncate font-[family-name:var(--font-jetbrains-mono)] text-xs text-[var(--color-text-secondary)]" title={finding.file_path}>
                        {finding.file_path}<span className="text-[var(--color-text-primary)]">:{finding.start_line}</span>
                      </p>
                      <div className="ml-auto flex shrink-0 items-center gap-1.5">
                        <a href={findingUrl} target="_blank" rel="noreferrer" className="text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]" aria-label={`View ${finding.file_path}:${finding.start_line} on GitHub (opens in new tab)`} title={`${finding.file_path}:${finding.start_line}`}>
                          <LinkIcon />
                          <span className="sr-only">(opens in new tab)</span>
                        </a>
                      </div>
                    </div>
                    {vulnerableCode ? (
                      <CodeLines
                        code={vulnerableCode}
                        startLine={codeWindowStart}
                        highlightIdx={codeHighlightIdx}
                        borderCls="border-[var(--color-border)]/60"
                        hlRowCls="bg-orange-500/15"
                      />
                    ) : (
                      <p className="px-3 pb-2.5 text-[11px] text-[var(--color-text-secondary)]">No code preview available</p>
                    )}
                  </div>

                  {/* Call graph — only when reachable */}
                  {verdict === "reachable" && (() => {
                    const chain = finding.reachability?.call_chain ?? []
                    return (
                      <div className="flex flex-col items-stretch">
                        {chain.length > 0 ? chain.map((step, idx) => {
                          const isEntry = idx === 0
                          const stepUrl = `https://github.com/${finding.repo_full_name}/blob/HEAD/${step.file}#L${step.line}`
                          return (
                            <div key={idx} className="flex flex-col items-stretch">
                              {idx > 0 && <Arrow />}
                              <div className={`rounded-lg border overflow-hidden ${isEntry ? "border-[var(--color-accent)]/30 bg-[var(--color-accent)]/5" : "border-[var(--color-border)] bg-[var(--color-surface-raised)]"}`}>
                                <div className="flex items-center gap-2 px-3 pt-2.5 pb-1">
                                  {isEntry ? (
                                    <svg className="h-3.5 w-3.5 shrink-0 text-[var(--color-accent)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                                      <path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z" />
                                    </svg>
                                  ) : (
                                    <span className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-[var(--color-border)]/60 text-[9px] font-bold tabular-nums text-[var(--color-text-secondary)]">
                                      {idx + 1}
                                    </span>
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
                                <p className="px-3 pb-1.5 font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-secondary)]" title={step.file}>
                                  {step.file}<span className="text-[var(--color-text-primary)]">:{step.line}</span>
                                </p>
                                {step.snippet && (
                                  <CodeLines
                                    code={step.snippet.trimEnd()}
                                    startLine={step.line}
                                    highlightIdx={0}
                                    borderCls={isEntry ? "border-[var(--color-accent)]/20" : "border-[var(--color-border)]/60"}
                                    hlRowCls={isEntry ? "bg-[var(--color-accent)]/15" : "bg-[var(--color-border)]/40"}
                                  />
                                )}
                              </div>
                            </div>
                          )
                        }) : (
                          <div className="rounded-lg border border-[var(--color-accent)]/30 bg-[var(--color-accent)]/5 px-3 py-2.5">
                            <div className="flex items-center gap-2">
                              <svg className="h-3.5 w-3.5 shrink-0 text-[var(--color-accent)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                                <path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z" />
                              </svg>
                              <span className="font-[family-name:var(--font-jetbrains-mono)] text-xs font-semibold text-[var(--color-accent)]">
                                {finding.reachability?.entry_point ?? "Entry point"}
                              </span>
                              <span className="ml-auto rounded-full bg-[var(--color-accent)]/10 px-1.5 py-0.5 text-[10px] font-medium text-[var(--color-accent)]">entry</span>
                            </div>
                            {finding.reachability?.entry_point === "module-level" && (
                              <p className="mt-1 text-[11px] text-[var(--color-text-secondary)]">Executes at module level on import</p>
                            )}
                          </div>
                        )}
                      </div>
                    )
                  })()}

                  {/* Reachability status note for non-reachable verdicts */}
                  {verdict === "unreachable" && (
                    <p className="text-[11px] text-[var(--color-text-secondary)]">Not reachable from any detected entry point — lower exploitation risk.</p>
                  )}
                  {verdict === "unknown" && (
                    <p className="text-[11px] text-[var(--color-text-secondary)]">Reachability could not be determined — treat as potentially reachable.</p>
                  )}

                </div>
              )
            })()}

            {/* AI Analysis tab — only renders content when selected */}
            {remediationTab === "ai" && (
              <div>
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
                )}
              </div>
            )}
          </DrawerSection>

          {/* ── 3. Advisory Details ── */}
          {finding.fix_suggestion && (
            <DrawerSection label="Advisory Details">
              <p className="text-sm leading-relaxed text-[var(--color-text-primary)]">
                {finding.fix_suggestion}
              </p>
            </DrawerSection>
          )}

          {/* ── 4. References ── */}
          {finding.cwe && finding.cwe.length > 0 && (
            <DrawerSection label="References">
              <div className="space-y-2">
                {finding.cwe.map((id) => <CweCard key={id} id={id} />)}
              </div>
            </DrawerSection>
          )}

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
