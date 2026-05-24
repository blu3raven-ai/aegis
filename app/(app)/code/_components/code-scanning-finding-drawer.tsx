"use client"

import { useEffect, useMemo, useState } from "react"
import { FindingsDrawerShell } from "@/components/shared/FindingsDrawerShell"
import {
  DrawerHeader,
  DrawerStatusBanner,
  DrawerSection,
  DrawerDetailGrid,
  DrawerFooter,
  DismissPopover,
  DrawerCodeLines,
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
  const [cweData, setCweData] = useState<Record<string, { name: string | null; description: string | null }>>({})
  useEffect(() => {
    if (!finding?.cwe?.length) return
    finding.cwe.forEach((id) => {
      const num = String(parseInt(id.replace(/^cwe-/i, ""), 10))
      if (cweData[num] !== undefined) return
      fetch(`/api/cwe/${num}`)
        .then((r) => r.json())
        .then((data: { name: string | null; description: string | null }) => {
          setCweData((prev) => ({ ...prev, [num]: { name: data.name ?? null, description: data.description ?? null } }))
        })
        .catch(() => {})
    })
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [finding?.identity_key])

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

const repoBaseUrl = finding?.repo_html_url || null
  const githubUrl = repoBaseUrl
    ? `${repoBaseUrl}/blob/HEAD/${finding!.file_path}#L${finding!.start_line}`
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
        eyebrow="Code Scanning Finding"
        title={finding?.rule_id ?? ""}
        titleTooltip={finding?.rule_id}
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
            <div className="flex items-center gap-3 flex-wrap">
              <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold capitalize ${severityBadgeClass(finding.severity)}`}>
                {finding.severity}
              </span>
              {finding.reachability && (() => {
                const cfg = reachabilityBadgeConfig(finding.reachability.verdict as ReachabilityVerdict)
                return (
                  <span
                    className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold ${cfg.cls}`}
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

            <h4 className="text-lg font-semibold text-[var(--color-text-primary)]">
              {firstSentence(finding.message)}
            </h4>

            {finding.cwe && finding.cwe.length > 0 && (
              <div className="flex flex-wrap items-center gap-2">
                {finding.cwe.map((id) => {
                  const normalised = id.toUpperCase().startsWith("CWE-") ? id.toUpperCase() : `CWE-${id}`
                  const num = String(parseInt(normalised.replace(/^CWE-/, ""), 10))
                  return (
                    <a
                      key={id}
                      href={`https://cwe.mitre.org/data/definitions/${num}.html`}
                      target="_blank"
                      rel="noreferrer"
                      className="cursor-pointer rounded-lg border border-[var(--color-border)] px-2.5 py-1 text-xs font-semibold text-[var(--color-accent)] hover:bg-[var(--color-surface-raised)]"
                    >
                      {normalised}
                    </a>
                  )
                })}
              </div>
            )}

            <DrawerDetailGrid items={briefDetails} />
          </DrawerSection>

          {/* ── 2. Remediation ── */}
          {(() => {
            const findingUrl = repoBaseUrl ? `${repoBaseUrl}/blob/HEAD/${finding.file_path}#L${finding.start_line}` : null
            const snippetTrimmed = (finding.snippet || "").trim()
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
                codeHighlightIdx = foundIdx
                codeWindowStart = finding.start_line - foundIdx
                vulnerableCode = rawWindow
              } else {
                codeWindowStart = Math.max(1, finding.start_line - 40)
                codeHighlightIdx = finding.start_line - codeWindowStart
                vulnerableCode = rawWindow
              }
            } else {
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

            return (
              <DrawerSection label="Remediation">
                {/* Fix guidance */}
                {finding.fix_suggestion && (
                  <div className="flex items-start gap-2">
                    <svg className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--color-text-secondary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <circle cx="12" cy="12" r="10" /><path d="M12 16v-4M12 8h.01" />
                    </svg>
                    <p className="text-xs leading-relaxed text-[var(--color-text-secondary)]">{finding.fix_suggestion}</p>
                  </div>
                )}

                {/* Affected location */}
                <div className="flex items-center justify-between gap-2">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)]">
                    Affected location
                    <span className="ml-1.5 normal-case tracking-normal font-normal opacity-60">· {finding.file_path}:{finding.start_line}</span>
                  </p>
                  {findingUrl && (
                    <a
                      href={findingUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="shrink-0 text-xs font-semibold text-[var(--color-accent)] hover:underline"
                    >
                      View in repository
                    </a>
                  )}
                </div>

                {/* Code block */}
                <div className="rounded-lg border border-[var(--color-border)] overflow-hidden">
                  <div className="border-b border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-1.5">
                    <p className="min-w-0 truncate font-[family-name:var(--font-jetbrains-mono)] text-xs font-semibold text-[var(--color-text-primary)]" title={finding.file_path}>
                      {finding.file_path}
                    </p>
                  </div>
                  {vulnerableCode ? (
                    <DrawerCodeLines
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

                {/* Call chain — only when reachable */}
                {verdict === "reachable" && (() => {
                  const chain = finding.reachability?.call_chain ?? []
                  return (
                    <div>
                      <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)]">Call chain</p>
                      <div className="flex flex-col items-stretch">
                        {chain.length > 0 ? chain.map((step, idx) => {
                          const isEntry = idx === 0
                          const stepUrl = repoBaseUrl ? `${repoBaseUrl}/blob/HEAD/${step.file}#L${step.line}` : null
                          return (
                            <div key={idx} className="flex flex-col items-stretch">
                              {idx > 0 && <Arrow />}
                              <div className={`rounded-lg border overflow-hidden ${isEntry ? "border-[var(--color-accent)]/30 bg-[var(--color-accent)]/5" : "border-[var(--color-border)]"}`}>
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
                                    {stepUrl && (
                                      <a href={stepUrl} target="_blank" rel="noreferrer" className="text-xs font-semibold text-[var(--color-accent)] hover:underline" aria-label={`View ${step.file}:${step.line} (opens in new tab)`}>
                                        View in repository
                                      </a>
                                    )}
                                  </div>
                                </div>
                                <p className="px-3 pb-1.5 font-[family-name:var(--font-jetbrains-mono)] text-[11px] font-semibold text-[var(--color-text-primary)]" title={step.file}>
                                  {step.file}<span className="opacity-50">:{step.line}</span>
                                </p>
                                {step.snippet && (
                                  <DrawerCodeLines
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
                    </div>
                  )
                })()}

                {verdict === "unreachable" && (
                  <p className="text-[11px] text-[var(--color-text-secondary)]">Not reachable from any detected entry point — lower exploitation risk.</p>
                )}
                {verdict === "unknown" && (
                  <p className="text-[11px] text-[var(--color-text-secondary)]">Reachability could not be determined — treat as potentially reachable.</p>
                )}
              </DrawerSection>
            )
          })()}

          {/* ── 3. AI Analysis ── */}
          {finding.ai_review && (
            <DrawerSection label="AI Analysis">
              {finding.ai_review.verdict !== "skipped" && (
                <div className="flex items-center gap-2">
                  {finding.ai_review.confidence && (
                    <span className="text-[11px] font-medium text-[var(--color-text-secondary)] capitalize">
                      {finding.ai_review.confidence} confidence
                    </span>
                  )}
                  <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${verdictChipClass(finding.ai_review.verdict)}`}>
                    {finding.ai_review.verdict}
                  </span>
                </div>
              )}
              <div className="space-y-3">
                {finding.ai_review.reasoning && (
                  <div>
                    <p className="mb-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)]">Reasoning</p>
                    <p className="text-xs leading-relaxed text-[var(--color-text-secondary)] whitespace-pre-wrap">{finding.ai_review.reasoning}</p>
                  </div>
                )}
                {finding.ai_review.explanation && (
                  <div>
                    <p className="mb-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)]">Explanation</p>
                    <p className="text-sm leading-relaxed text-[var(--color-text-primary)]">{finding.ai_review.explanation}</p>
                  </div>
                )}
              </div>
            </DrawerSection>
          )}

          {/* ── 3. Advisory Details ── */}
          <DrawerSection label="Advisory Details">
            <p className="text-sm leading-relaxed text-[var(--color-text-primary)]">
              {finding.message}
            </p>
            {finding.cwe?.map((id) => {
              const num = String(parseInt(id.replace(/^cwe-/i, ""), 10))
              const entry = cweData[num]
              if (!entry?.description) return null
              return (
                <div key={id} className="mt-3">
                  <p className="mb-1 text-xs font-semibold text-[var(--color-text-secondary)]">CWE-{num}</p>
                  <p className="text-sm leading-relaxed text-[var(--color-text-primary)]">{entry.description}</p>
                </div>
              )
            })}
            {finding.fix_suggestion && (
              <p className="mt-3 text-sm leading-relaxed text-[var(--color-text-secondary)]">
                {finding.fix_suggestion}
              </p>
            )}
          </DrawerSection>

          {/* ── 4. References ── */}
          {finding.cwe && finding.cwe.length > 0 && (
            <DrawerSection label="References">
              <div className="space-y-2">
                {finding.cwe.map((id) => {
                  const normalised = id.toUpperCase().startsWith("CWE-") ? id.toUpperCase() : `CWE-${id}`
                  const num = String(parseInt(normalised.replace(/^CWE-/, ""), 10))
                  const url = `https://cwe.mitre.org/data/definitions/${num}.html`
                  const label = `cwe.mitre.org/data/definitions/${num}`
                  return (
                    <a
                      key={id}
                      href={url}
                      target="_blank"
                      rel="noreferrer"
                      className="flex min-w-0 items-center justify-between gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 text-xs font-medium text-[var(--color-accent)] transition-colors hover:bg-[var(--color-surface)] cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
                      title={url}
                    >
                      <span className="truncate">{label}</span>
                      <span className="shrink-0 text-[var(--color-text-secondary)]">Open →</span>
                    </a>
                  )
                })}
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
