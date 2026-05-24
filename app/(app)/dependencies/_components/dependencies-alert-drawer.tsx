"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import { gqlQuery } from "@/lib/client/graphql-client"
import type { GqlDependenciesFindingDetail } from "@/lib/shared/graphql/types"
import { DEPENDENCIES_FINDING_DETAIL_QUERY } from "@/lib/shared/graphql/queries"
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
import {
  DrawerHeader,
  DrawerStatusBanner,
  DrawerSection,
  DrawerDetailGrid,
  DrawerFooter,
  DismissPopover,
  DrawerCodeBlock,
} from "@/components/shared/FindingDrawer"

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
          <blockquote className="rounded-md bg-[var(--color-surface-raised)] px-3 py-2 text-sm italic text-[var(--color-text-secondary)]">
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
    <DrawerSection label="References">
      <p className="text-xs text-[var(--color-text-secondary)]">
        Source links from the advisory.
      </p>
      <div className="space-y-2">
        {references.map((reference) => (
          <a
            key={reference.url}
            href={reference.url}
            onClick={(e) => onLinkClick(e, reference.url)}
            className="flex min-w-0 items-center justify-between gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 text-xs font-medium text-[var(--color-accent)] transition-colors hover:bg-[var(--color-surface)] cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
            title={reference.url}
          >
            <span className="truncate">{formatReferenceLabel(reference.url)}</span>
            <span className="shrink-0 text-[var(--color-text-secondary)]">Open →</span>
          </a>
        ))}
      </div>
    </DrawerSection>
  )
}

export function DependenciesAlertDrawer({ finding, relatedFindings = [], org, onClose, onStateChange, dismissFn, reopenFn }: Props) {
  const [actionLoading, setActionLoading] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const [detailMap, setDetailMap] = useState<Map<string, GqlDependenciesFindingDetail>>(new Map())
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState(false)
  const [snippetIndex, setSnippetIndex] = useState(0)

  const allFindings = useMemo(() => relatedFindings.length > 0 ? relatedFindings : finding ? [finding] : [], [relatedFindings, finding])

  // Advisory-level detail from the primary finding
  const detail = finding ? (detailMap.get(findingIdentityKey(finding)) ?? null) : null

  // Findings that have a manifest snippet — drives the navigator
  const snippetFindings = useMemo(
    () => allFindings.filter((f) => detailMap.get(findingIdentityKey(f))?.manifestSnippet),
    [allFindings, detailMap],
  )

  useEffect(() => {
    setActionError(null)
  }, [finding])

  useEffect(() => {
    setSnippetIndex(0)
  }, [finding])

  useEffect(() => {
    if (!finding) {
      setDetailMap(new Map())
      setDetailLoading(false)
      setDetailError(false)
      return
    }
    let cancelled = false
    setDetailMap(new Map())
    setDetailLoading(true)
    setDetailError(false)
    const targets = relatedFindings.length > 0 ? relatedFindings : [finding]
    Promise.all(
      targets.map((f) =>
        gqlQuery<{ dependenciesFindingDetail: GqlDependenciesFindingDetail | null }>(
          DEPENDENCIES_FINDING_DETAIL_QUERY,
          { org, identityKey: findingIdentityKey(f) },
        ).then(({ dependenciesFindingDetail }) => ({
          key: findingIdentityKey(f),
          data: dependenciesFindingDetail,
        }))
      )
    )
      .then((results) => {
        if (cancelled) return
        const map = new Map<string, GqlDependenciesFindingDetail>()
        for (const { key, data } of results) {
          if (data) map.set(key, data)
        }
        setDetailMap(map)
      })
      .catch(() => {
        if (!cancelled) setDetailError(true)
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false)
      })
    return () => { cancelled = true }
  }, [finding, org, relatedFindings])

  // Escape key handling moved to FindingsDrawerShell

  async function handleDismiss(reason: string) {
    if (!finding) return
    setActionLoading(true)
    setActionError(null)
    try {
      const identityKey = findingIdentityKey(finding)
      await dismissFn?.(org, identityKey, reason)
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

  const sev    = finding?.security_advisory.severity ?? ""
  const cvss   = finding?.security_advisory.cvss.score ?? null
  const ghsaId = detail?.ghsaId ?? finding?.security_advisory.ghsa_id ?? ""
  const cveId  = detail?.cveId ?? null
  // ghsa_id sometimes contains a CVE (Grype uses CVE as primary for Go modules)
  const isRealGhsa = ghsaId.startsWith("GHSA-")
  const isRealCve = (cveId ?? "").startsWith("CVE-")
  // If ghsa_id is actually a CVE and cve_id is empty, use ghsa_id as the CVE
  const effectiveCveId = isRealCve ? (cveId ?? "") : (!isRealGhsa && ghsaId.startsWith("CVE-")) ? ghsaId : ""
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
    <FindingsDrawerShell open={!!finding} onClose={onClose} label="Dependency finding details">
      <DrawerHeader
        eyebrow="Dependencies Scanning Finding"
        title={finding ? finding.dependency.package.name : "Select a finding"}
        onClose={onClose}
      />
      {finding && (
        <DrawerStatusBanner
          state={finding.state as "open" | "dismissed" | "fixed" | "awaiting_fix" | "deferred"}
          dismissedReason={finding.dismissed_reason ?? undefined}
          onReopen={() => void handleReopen()}
        />
      )}

      <div className="flex-1 overflow-y-auto p-5">
        {!finding ? (
          <div className="flex min-h-[460px] items-center justify-center rounded-xl border border-dashed border-[var(--color-border)] px-6 text-center text-sm text-[var(--color-text-secondary)]">
            Select a finding to view details.
          </div>
        ) : (
          <div className="space-y-5">
            {/* Advisory metadata */}
            <DrawerSection label="Security brief">
              <div className="flex items-center gap-3 flex-wrap">
                <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${SEV_BADGE[sev] ?? ""}`}>
                  {sev || "-"}
                </span>
                <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold tabular-nums ${cvssChipClass(cvss)}`}>
                  CVSS {formatCvssScore(cvss)}
                </span>
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

              {detail?.cvssVector && (
                <p className="break-all rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 font-[family-name:var(--font-jetbrains-mono)] text-xs text-[var(--color-text-secondary)]">
                  {detail.cvssVector}
                </p>
              )}

              <DrawerDetailGrid
                items={[
                  { label: "Affected range", value: vulnerableRange },
                  { label: "Patched version", value: patchedVersion },
                  { label: "Published", value: formatDate(detail?.publishedAt ?? "") },
                  { label: "Updated", value: formatDate(detail?.advisoryUpdatedAt ?? "") },
                ]}
              />

            </DrawerSection>

            {/* Remediation */}
            <DrawerSection label="Remediation">

              {/* Version upgrade */}
              <div className="space-y-1.5">
                <VersionLine alert={finding} />
                <p className="text-xs leading-relaxed text-[var(--color-text-secondary)]">
                  {alertPatchVersion(finding)
                    ? <>Upgrade <span className="font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-primary)]">{finding.dependency.package.name}</span> to <span className="font-[family-name:var(--font-jetbrains-mono)] text-emerald-400">{alertPatchVersion(finding)}</span> or later in your dependency manifest, then re-lock and redeploy.</>
                    : <>No patch is currently available for <span className="font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-primary)]">{finding.dependency.package.name}</span>. Monitor the advisory and consider removing or replacing this dependency until a fix is released.</>
                  }
                </p>
              </div>

              {/* Affected manifests list */}
              <div className="space-y-2">
                <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
                  Affected locations ({allFindings.length})
                </p>
                <div className="space-y-1">
                  {allFindings.map((f, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 transition-colors"
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
                          requestNavigation(`https://github.com/${repoPath}/blob/HEAD/${manifestPath}${detail?.manifestMatchLine ? `#L${detail.manifestMatchLine}` : ""}`)
                        }}
                        className="shrink-0 text-xs font-semibold text-[var(--color-accent)] hover:underline"
                      >
                        View in repository
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              {/* Manifest file preview with navigator when multiple locations have snippets */}
              {detailLoading && (
                <div className="animate-pulse space-y-2 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4">
                  <div className="h-3 w-1/3 rounded bg-[var(--color-border)]" />
                  <div className="h-3 w-full rounded bg-[var(--color-border)]" />
                  <div className="h-3 w-4/5 rounded bg-[var(--color-border)]" />
                </div>
              )}
              {!detailLoading && snippetFindings.length > 0 && (() => {
                const safeIndex = Math.min(snippetIndex, snippetFindings.length - 1)
                const f = snippetFindings[safeIndex]
                const fDetail = detailMap.get(findingIdentityKey(f))!
                const snippet = fDetail.manifestSnippet!
                const matchLine = fDetail.manifestMatchLine
                if (/[\x00-\x08\x0E-\x1F]/.test(snippet)) return null
                const startLineNum = matchLine != null ? Math.max(1, matchLine - 7) : 1
                const filename = f.dependency.manifest_path?.split("/").filter(Boolean).pop() ?? f.dependency.manifest_path ?? ""
                const nav = snippetFindings.length > 1 ? (
                  <div className="flex items-center gap-1">
                    <button
                      type="button"
                      aria-label="Previous manifest"
                      onClick={() => setSnippetIndex((i) => Math.max(0, i - 1))}
                      disabled={safeIndex === 0}
                      className="flex h-5 w-5 items-center justify-center rounded text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)] disabled:cursor-not-allowed disabled:opacity-30"
                    >
                      <svg width="10" height="10" viewBox="0 0 10 10" fill="none" aria-hidden>
                        <path d="M6.5 2L3.5 5L6.5 8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                      </svg>
                    </button>
                    <span className="font-[family-name:var(--font-jetbrains-mono)] text-[11px] tabular-nums text-[var(--color-text-secondary)]">
                      {safeIndex + 1}/{snippetFindings.length}
                    </span>
                    <button
                      type="button"
                      aria-label="Next manifest"
                      onClick={() => setSnippetIndex((i) => Math.min(snippetFindings.length - 1, i + 1))}
                      disabled={safeIndex === snippetFindings.length - 1}
                      className="flex h-5 w-5 items-center justify-center rounded text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)] disabled:cursor-not-allowed disabled:opacity-30"
                    >
                      <svg width="10" height="10" viewBox="0 0 10 10" fill="none" aria-hidden>
                        <path d="M3.5 2L6.5 5L3.5 8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                      </svg>
                    </button>
                  </div>
                ) : undefined
                return (
                  <DrawerCodeBlock
                    lines={snippet.split("\n").map((line, idx) => ({
                      number: startLineNum + idx,
                      content: line,
                      highlighted: matchLine != null && (startLineNum + idx) === matchLine,
                    }))}
                    label={filename}
                    lineRange={nav}
                    maxHeight={320}
                  />
                )
              })()}
            </DrawerSection>

            {/* Advisory description */}
            <DrawerSection label="Advisory details">
              <p className="text-xs text-[var(--color-text-secondary)]">
                Details from the security advisory.
              </p>
              {detailLoading ? (
                <div className="animate-pulse space-y-2">
                  <div className="h-3 w-3/4 rounded bg-[var(--color-border)]" />
                  <div className="h-3 w-full rounded bg-[var(--color-border)]" />
                  <div className="h-3 w-5/6 rounded bg-[var(--color-border)]" />
                </div>
              ) : detailError ? (
                <p className="text-sm text-[var(--color-text-secondary)]">Advisory details unavailable.</p>
              ) : (
                <AdvisoryDescription
                  content={detail?.advisoryDescription ?? ""}
                  onLinkClick={handleExternalClick}
                />
              )}
            </DrawerSection>

            {!detailLoading && !detailError && (
              <AdvisoryReferences
                references={(detail?.references ?? []).map((url) => ({ url }))}
                onLinkClick={handleExternalClick}
              />
            )}
          </div>
        )}
      </div>

      <DrawerFooter>
        {actionError && <p className="mb-3 text-xs text-red-500">{actionError}</p>}
        {(finding?.state === "open" || finding?.state === "deferred") && (
          <DismissPopover
            reasons={DISMISS_REASONS}
            onDismiss={(reason) => void handleDismiss(reason)}
            isLoading={actionLoading}
          />
        )}
      </DrawerFooter>
      <ExternalLinkConfirm url={pendingUrl} onClose={closeExtLink} />
    </FindingsDrawerShell>
  )
}
