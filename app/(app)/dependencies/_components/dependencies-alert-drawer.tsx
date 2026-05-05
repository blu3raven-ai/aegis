"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import { FindingsDrawerShell } from "@/components/shared/FindingsDrawerShell"
import Markdown from "react-markdown"
import remarkGfm from "remark-gfm"
import type { DependenciesFinding } from "@/lib/shared/dependencies/types"
import { alertPatchVersion, cvssChipClass, DISMISS_REASONS, findingIdentityKey, formatCvssScore } from "@/lib/shared/dependencies/utils"
import { ExternalLinkConfirm, useExternalLinkConfirm } from "@/components/shared/ExternalLinkConfirm"
import { formatDate } from "@/lib/shared/utils"

type DismissFn = (org: string, identityKey: string, reason: string) => Promise<unknown>
type ReopenFn = (org: string, identityKey: string) => Promise<unknown>

import { SEV_BADGE } from "@/lib/shared/ui/badge-styles"

function VersionLine({ alert }: { alert: DependenciesFinding }) {
  const current = alert.current_version ?? null
  const patch = alertPatchVersion(alert)

  if (!current && !patch) {
    return (
      <p className="font-[family-name:var(--font-jetbrains-mono)] text-sm text-[var(--color-text-secondary)]">
        {alert.security_vulnerability.vulnerable_version_range || "Version range unavailable"}
      </p>
    )
  }

  return (
    <p className="flex items-center gap-1.5 font-[family-name:var(--font-jetbrains-mono)] text-sm">
      <span className="text-[var(--color-text-primary)]">{current ?? "Unknown"}</span>
      <span className="text-[var(--color-text-secondary)]">→</span>
      {patch ? (
        <span className="text-emerald-400">{patch}</span>
      ) : (
        <span className="text-[var(--color-text-secondary)]">No patch available</span>
      )}
    </p>
  )
}


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

interface Props {
  finding: DependenciesFinding | null
  /** All manifest variants for this advisory (same GHSA + package in this repo) */
  relatedFindings?: DependenciesFinding[]
  org: string
  onClose: () => void
  onStateChange?: () => void
  dismissFn?: DismissFn
  reopenFn?: ReopenFn
}

function formatReferenceLabel(url: string): string {
  try {
    const parsed = new URL(url)
    const path = parsed.pathname.replace(/\/$/, "")
    const shortPath = path.length > 48 ? `${path.slice(0, 45)}...` : path
    return `${parsed.hostname}${shortPath}`
  } catch {
    return url.length > 56 ? `${url.slice(0, 53)}...` : url
  }
}

/** Sanitized markdown renderer for advisory descriptions. Uses react-markdown (no dangerouslySetInnerHTML, no raw HTML passthrough). */
function AdvisoryDescription({ content, onLinkClick }: { content: string; onLinkClick: (e: React.MouseEvent<HTMLAnchorElement>, url: string) => void }) {
  if (!content.trim()) {
    return (
      <p className="text-sm text-[var(--color-text-secondary)]">
        Advisory description unavailable.
      </p>
    )
  }

  return (
    <Markdown
      remarkPlugins={[remarkGfm]}
      skipHtml
      components={{
        h1: ({ children }) => <h2 className="mb-4 mt-8 text-lg font-bold text-[var(--color-text-primary)]">{children}</h2>,
        h2: ({ children }) => <h3 className="mb-3 mt-6 text-base font-bold text-[var(--color-text-primary)]">{children}</h3>,
        h3: ({ children }) => <h4 className="mb-2 mt-4 text-sm font-bold text-[var(--color-text-primary)]">{children}</h4>,
        h4: ({ children }) => <h5 className="mb-1 mt-3 text-sm font-semibold text-[var(--color-text-primary)]">{children}</h5>,
        p: ({ children }) => <p className="text-sm leading-relaxed text-[var(--color-text-secondary)]">{children}</p>,
        strong: ({ children }) => <strong className="font-bold text-[var(--color-text-primary)]">{children}</strong>,
        a: ({ href, children }) => (
          <a href={href ?? "#"} onClick={(e) => { if (href) onLinkClick(e, href) }} className="cursor-pointer text-[var(--color-accent)] hover:underline">
            {children}
          </a>
        ),
        ul: ({ children }) => <ul className="space-y-1.5 pl-4 list-disc marker:text-[var(--color-accent)]">{children}</ul>,
        ol: ({ children }) => <ol className="space-y-1.5 pl-4 list-decimal marker:text-[var(--color-text-secondary)]">{children}</ol>,
        li: ({ children }) => <li className="text-sm leading-relaxed text-[var(--color-text-secondary)]">{children}</li>,
        code: ({ className, children }) => {
          const isBlock = className?.startsWith("language-")
          if (isBlock) {
            return (
              <pre className="overflow-x-auto rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4 font-mono text-xs leading-relaxed text-[var(--color-text-primary)]">
                <code>{children}</code>
              </pre>
            )
          }
          return (
            <code className="rounded border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-1 py-0.5 font-mono text-[13px] text-[var(--color-text-primary)]">
              {children}
            </code>
          )
        },
        pre: ({ children }) => <>{children}</>,
        img: ({ src, alt }) => (
          <img
            src={src}
            alt={alt ?? ""}
            className="max-w-full rounded-xl border border-[var(--color-border)]"
            loading="lazy"
          />
        ),
        blockquote: ({ children }) => (
          <blockquote className="border-l-2 border-[var(--color-accent)] pl-3 text-sm italic text-[var(--color-text-secondary)]">
            {children}
          </blockquote>
        ),
        table: ({ children }) => (
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-[var(--color-text-secondary)]">{children}</table>
          </div>
        ),
        th: ({ children }) => <th className="border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-1.5 text-left text-xs font-semibold text-[var(--color-text-primary)]">{children}</th>,
        td: ({ children }) => <td className="border border-[var(--color-border)] px-3 py-1.5">{children}</td>,
        hr: () => <hr className="border-[var(--color-border)]" />,
      }}
    >
      {content}
    </Markdown>
  )
}

function AdvisoryReferences({ references, onLinkClick }: { references: { url: string }[]; onLinkClick: (e: React.MouseEvent<HTMLAnchorElement>, url: string) => void }) {
  if (references.length === 0) return null

  return (
    <section className="space-y-3 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
      <div>
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--color-text-secondary)]">
          References
        </p>
        <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
          Source links from the advisory.
        </p>
      </div>
      <div className="space-y-2">
        {references.map((reference) => (
          <a
            key={reference.url}
            href={reference.url}
            onClick={(e) => onLinkClick(e, reference.url)}
            className="flex min-w-0 items-center justify-between gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 text-xs font-medium text-orange-400 transition-colors hover:bg-[var(--color-surface)] cursor-pointer"
            title={reference.url}
          >
            <span className="truncate">{formatReferenceLabel(reference.url)}</span>
            <span className="shrink-0 text-[var(--color-text-secondary)]">Open →</span>
          </a>
        ))}
      </div>
    </section>
  )
}

export function DependenciesAlertDrawer({ finding, relatedFindings = [], org, onClose, onStateChange, dismissFn, reopenFn }: Props) {
  const [dismissOpen, setDismissOpen] = useState(false)
  const [actionLoading, setActionLoading] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const [previewIndex, setPreviewIndex] = useState(0)

  const allFindings = useMemo(() => relatedFindings.length > 0 ? relatedFindings : finding ? [finding] : [], [relatedFindings, finding])
  const snippetFindings = useMemo(() => allFindings.filter((f) => f.manifest_snippet), [allFindings])

  useEffect(() => {
    setDismissOpen(false)
    setPreviewIndex(0)
  }, [finding])

  // Escape key handling moved to FindingsDrawerShell

  async function handleDismiss(reason: string) {
    if (!finding) return
    setActionLoading(true)
    setActionError(null)
    try {
      const identityKey = findingIdentityKey(finding)
      await dismissFn?.(org, identityKey, reason)
      setDismissOpen(false)
      onStateChange?.()
    } catch {
      setActionError("Failed to dismiss finding. Please try again.")
    } finally {
      setActionLoading(false)
    }
  }

  async function handleReopen() {
    if (!finding) return
    setActionLoading(true)
    setActionError(null)
    try {
      const identityKey = findingIdentityKey(finding)
      await reopenFn?.(org, identityKey)
      onStateChange?.()
    } catch {
      setActionError("Failed to reopen finding. Please try again.")
    } finally {
      setActionLoading(false)
    }
  }

  const sev  = finding?.security_advisory.severity ?? ""
  const cvss = finding?.security_advisory.cvss.score ?? null
  const ghsaId = finding?.security_advisory.ghsa_id ?? ""
  const cveId = finding?.security_advisory.cve_id ?? ""
  // ghsa_id sometimes contains a CVE (Grype uses CVE as primary for Go modules)
  const isRealGhsa = ghsaId.startsWith("GHSA-")
  const isRealCve = cveId.startsWith("CVE-")
  // If ghsa_id is actually a CVE and cve_id is empty, use ghsa_id as the CVE
  const effectiveCveId = isRealCve ? cveId : (!isRealGhsa && ghsaId.startsWith("CVE-")) ? ghsaId : ""
  const ghsaUrl = isRealGhsa ? `https://github.com/advisories/${ghsaId}` : null
  const cveUrl = effectiveCveId ? `https://nvd.nist.gov/vuln/detail/${effectiveCveId}` : null

  const references = finding?.security_advisory.references.filter((reference) => reference.url) ?? []
  const patchedVersion = finding?.security_vulnerability.first_patched_version?.identifier ?? "-"
  const vulnerableRange = finding?.security_vulnerability.vulnerable_version_range || "-"

  const { pendingUrl, requestNavigation, close: closeExtLink } = useExternalLinkConfirm()

  const handleExternalClick = useCallback((e: React.MouseEvent<HTMLAnchorElement>, url: string) => {
    e.preventDefault()
    requestNavigation(url)
  }, [requestNavigation])

  return (
    <FindingsDrawerShell open={!!finding} onClose={onClose}>
      {/* Header */}
      <div className="flex items-start justify-between gap-4 border-b border-[var(--color-border)] p-5">
        <div className="min-w-0">
          <p className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">
            Vulnerability Details
          </p>
          <h3 className="mt-2 truncate text-xl font-semibold text-[var(--color-text-primary)]">
            {finding ? finding.dependency.package.name : "Select a finding"}
          </h3>
          {finding && (
            <span className="mt-1 inline-block rounded-full border border-[var(--color-border)] px-2.5 py-0.5 text-xs font-medium text-[var(--color-text-secondary)]">
              {finding.dependency.package.ecosystem}
            </span>
          )}
        </div>

        <div className="flex shrink-0 items-center gap-2">
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

      <div className="p-5">
        {!finding ? (
          <div className="flex min-h-[460px] items-center justify-center rounded-xl border border-dashed border-[var(--color-border)] px-6 text-center text-sm text-[var(--color-text-secondary)]">
            Select a finding to view details.
          </div>
        ) : (
          <div className="space-y-6">
            {/* Deferred banner */}
            {finding.state === "deferred" && (
              <div className="flex items-start gap-3 rounded-2xl border border-orange-500/20 bg-orange-500/8 p-4">
                <span className="mt-0.5 text-orange-400">⏳</span>
                <div>
                  <p className="text-sm font-medium text-orange-400">Deferred — no patch available</p>
                  <p className="mt-1 text-xs text-orange-400/70">
                    This vulnerability has no fix yet. It will automatically move to Open when a patch becomes available.
                  </p>
                </div>
              </div>
            )}

            {/* Dismiss / Reopen actions */}
            {finding.state === "dismissed" ? (
              <div className="flex items-center justify-between rounded-2xl border border-purple-500/20 bg-purple-500/8 p-4">
                <div>
                  <p className="text-sm font-medium text-purple-400">Dismissed</p>
                  {finding.dismissed_reason && (
                    <p className="mt-0.5 text-xs text-purple-400/70">Reason: {finding.dismissed_reason}</p>
                  )}
                </div>
                <button
                  type="button"
                  onClick={() => void handleReopen()}
                  disabled={actionLoading}
                  className="rounded-lg border border-purple-500/30 bg-[var(--color-surface-raised)] px-3 py-1.5 text-xs font-semibold text-purple-400 hover:bg-[var(--color-surface)] disabled:opacity-50"
                >
                  Reopen
                </button>
              </div>
            ) : (finding.state === "open" || finding.state === "deferred") && (
              <div className="relative">
                <button
                  type="button"
                  onClick={() => setDismissOpen(!dismissOpen)}
                  disabled={actionLoading}
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
                        disabled={actionLoading}
                        className="w-full rounded-lg px-2 py-1.5 text-left text-sm text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)] disabled:opacity-50"
                      >
                        {reason}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}

            {actionError && (
              <p className="text-sm text-red-400">{actionError}</p>
            )}

            {/* Advisory metadata */}
            <section className="space-y-4 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
              <div className="flex items-center justify-between gap-3">
                <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--color-text-secondary)]">
                  Security brief
                </p>
                <div className="flex flex-wrap gap-2">
                  <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${SEV_BADGE[sev] ?? ""}`}>
                    {sev || "-"}
                  </span>
                  <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold tabular-nums ${cvssChipClass(cvss)}`}>
                    CVSS {formatCvssScore(cvss)}
                  </span>
                </div>
              </div>

              <h4 className="text-lg font-semibold text-[var(--color-text-primary)]">
                {finding.security_advisory.summary || "Advisory summary unavailable"}
              </h4>

              <div className="flex flex-wrap items-center gap-2">
                {cveUrl && (
                  <a href={cveUrl} onClick={(e) => handleExternalClick(e, cveUrl)} className="cursor-pointer rounded-lg border border-[var(--color-border)] px-2.5 py-1 text-xs font-semibold text-[var(--color-accent)] hover:bg-[var(--color-surface-raised)]">
                    {effectiveCveId}
                  </a>
                )}
                {ghsaUrl && (
                  <a href={ghsaUrl} onClick={(e) => handleExternalClick(e, ghsaUrl)} className="cursor-pointer rounded-lg border border-[var(--color-border)] px-2.5 py-1 text-xs font-semibold text-[var(--color-accent)] hover:bg-[var(--color-surface-raised)]">
                    {ghsaId}
                  </a>
                )}
              </div>

              {finding.security_advisory.cvss.vector_string && (
                <p className="break-all rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 font-[family-name:var(--font-jetbrains-mono)] text-xs text-[var(--color-text-secondary)]">
                  {finding.security_advisory.cvss.vector_string}
                </p>
              )}

              <div className="grid gap-3 sm:grid-cols-2">
                <DetailItem label="Affected range" value={vulnerableRange} />
                <DetailItem label="Patched version" value={patchedVersion} />
                <DetailItem label="Published" value={formatDate(finding.security_advisory.published_at)} />
                <DetailItem label="Updated" value={formatDate(finding.security_advisory.updated_at)} />
              </div>

            </section>

            {/* Remediation */}
            <section className="space-y-4 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--color-text-secondary)]">
                Remediation
              </p>

              {/* Version upgrade */}
              <div className="flex items-center gap-3">
                <VersionLine alert={finding} />
              </div>

              {/* Affected manifests list */}
              <div className="space-y-2">
                <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
                  Affected locations ({allFindings.length})
                </p>
                <div className="space-y-1">
                  {allFindings.map((f, i) => {
                    const snippetIdx = snippetFindings.indexOf(f)
                    const isActive = snippetIdx >= 0 && snippetIdx === previewIndex
                    const hasSnippet = snippetIdx >= 0
                    return (
                      <div
                        key={i}
                        onClick={hasSnippet ? () => setPreviewIndex(snippetIdx) : undefined}
                        className={`flex items-center gap-2 rounded-lg border px-3 py-2 transition-colors ${
                          isActive
                            ? "border-[var(--color-accent)]/40 bg-[var(--color-accent)]/5"
                            : "border-[var(--color-border)] bg-[var(--color-surface-raised)]"
                        } ${hasSnippet ? "cursor-pointer hover:border-[var(--color-accent)]/30" : ""}`}
                      >
                        <span
                          className="min-w-0 flex-1 truncate font-[family-name:var(--font-jetbrains-mono)] text-xs text-[var(--color-text-primary)]"
                          title={f.dependency.manifest_path}
                        >
                          {f.dependency.manifest_path}
                        </span>
                        {f.current_version && (
                          <span className="shrink-0 font-[family-name:var(--font-jetbrains-mono)] text-xs text-[var(--color-text-secondary)]">
                            @{f.current_version}
                          </span>
                        )}
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation()
                            e.preventDefault()
                            const repoPath = f.repository.full_name.includes("/") ? f.repository.full_name : `${f.repository.full_name}/${f.repository.name}`
                            const manifestPath = (f.dependency.manifest_path || "").replace(/^\/+/, "")
                            requestNavigation(`https://github.com/${repoPath}/blob/HEAD/${manifestPath}${f.manifest_match_line ? `#L${f.manifest_match_line}` : ""}`)
                          }}
                          className="shrink-0 text-xs font-semibold text-[var(--color-accent)] hover:underline"
                        >
                          View in repository
                        </button>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Manifest file preview carousel */}
              {snippetFindings.length > 0 && (() => {
                const safeIdx = Math.min(previewIndex, snippetFindings.length - 1)
                const previewFinding = snippetFindings[safeIdx]
                if (!previewFinding?.manifest_snippet) return null

                if (/[\x00-\x08\x0E-\x1F]/.test(previewFinding.manifest_snippet)) {
                  return (
                    <div className="flex min-h-[80px] items-center justify-center rounded-xl border border-dashed border-[var(--color-border)] text-sm text-[var(--color-text-secondary)]">
                      Binary file — cannot display preview.
                    </div>
                  )
                }
                return (
                  <div>
                    <div className="mb-2 flex items-center gap-2">
                      {snippetFindings.length > 1 && (
                        <button
                          type="button"
                          onClick={() => setPreviewIndex((i) => (i - 1 + snippetFindings.length) % snippetFindings.length)}
                          className="rounded p-0.5 text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                          aria-label="Previous manifest"
                        >
                          <svg className="h-4 w-4" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M12.707 5.293a1 1 0 010 1.414L9.414 10l3.293 3.293a1 1 0 01-1.414 1.414l-4-4a1 1 0 010-1.414l4-4a1 1 0 011.414 0z" clipRule="evenodd" /></svg>
                        </button>
                      )}
                      <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
                        Preview — {previewFinding.dependency.manifest_path}
                        {snippetFindings.length > 1 && (
                          <span className="ml-1.5 font-normal normal-case">({safeIdx + 1} of {snippetFindings.length})</span>
                        )}
                      </p>
                      {snippetFindings.length > 1 && (
                        <button
                          type="button"
                          onClick={() => setPreviewIndex((i) => (i + 1) % snippetFindings.length)}
                          className="rounded p-0.5 text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                          aria-label="Next manifest"
                        >
                          <svg className="h-4 w-4" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clipRule="evenodd" /></svg>
                        </button>
                      )}
                    </div>
                    <div className="max-h-[320px] overflow-auto rounded-xl border border-[var(--color-border)] bg-slate-100 dark:bg-slate-950">
                      <pre className="min-w-max p-4 text-sm leading-6 text-slate-700 dark:text-slate-300">
                        <code>
                          {previewFinding.manifest_snippet.split("\n").map((line, idx) => {
                            const lineNum = (previewFinding.manifest_match_line ?? 1) - 7 + idx
                            const isMatch = previewFinding.manifest_match_line != null && lineNum === previewFinding.manifest_match_line
                            return (
                              <span
                                key={idx}
                                className={`block ${isMatch ? "-mx-4 bg-orange-500/15 px-4 text-orange-700 dark:text-orange-100" : ""}`}
                              >
                                <span className="mr-5 inline-block w-12 select-none text-right font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-secondary)]">
                                  {lineNum > 0 ? lineNum : idx + 1}
                                </span>
                                <span>{line || " "}</span>
                              </span>
                            )
                          })}
                        </code>
                      </pre>
                    </div>
                  </div>
                )
              })()}
            </section>

            {/* Advisory description */}
            <section className="space-y-4 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--color-text-secondary)]">
                  Advisory details
                </p>
                <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
                  Details from the security advisory.
                </p>
              </div>
              <AdvisoryDescription content={finding.security_advisory.description} onLinkClick={handleExternalClick} />
            </section>

            <AdvisoryReferences references={references} onLinkClick={handleExternalClick} />
          </div>
        )}
      </div>

      <ExternalLinkConfirm url={pendingUrl} onClose={closeExtLink} />
    </FindingsDrawerShell>
  )
}
