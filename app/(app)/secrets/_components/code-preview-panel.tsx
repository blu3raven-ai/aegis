"use client"

import type { CodePreviewResponse } from "@/lib/client/secrets/dashboard-client"
import { FindingsDrawerShell } from "@/components/shared/FindingsDrawerShell"
import { findingUiIdentity, reviewStatusLabel, reviewTone } from "@/lib/shared/secrets/dashboard-utils"
import type { SecretFinding, SecretReviewStatus } from "@/lib/shared/secrets/types"
import { ReviewActionButtons } from "@/app/(app)/secrets/_components/review-action-buttons"
import { DetectionHistoryPanel } from "@/app/(app)/secrets/_components/detection-history-panel"

interface Props {
  finding: SecretFinding | null
  preview: CodePreviewResponse | null
  relatedFindings: SecretFinding[]
  isLoading: boolean
  error: string | null
  canReview?: boolean
  onSelectRelated: (finding: SecretFinding) => void
  onReview?: (status: SecretReviewStatus) => void
  onClose: () => void
}

export function CodePreviewPanel({
  finding,
  preview,
  relatedFindings,
  isLoading,
  error,
  canReview,
  onSelectRelated,
  onReview,
  onClose,
}: Props) {
  const evidenceValue = finding?.secretSnippet?.trim() || "Not available"
  const keyOccurrenceCount = relatedFindings.length + (finding ? 1 : 0)

  return (
    <FindingsDrawerShell open={!!finding} onClose={onClose}>
      <div className="flex items-start justify-between gap-4 border-b border-[var(--color-border)] p-5">
        <div className="min-w-0">
          <p className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">Code Preview</p>
          <h3 className="mt-2 truncate text-xl font-semibold text-[var(--color-text-primary)]">
            {finding ? `${finding.organization}/${finding.repository}` : "Select a finding"}
          </h3>
          <p className="mt-1 truncate font-[family-name:var(--font-jetbrains-mono)] text-xs text-[var(--color-text-secondary)]">
            {finding?.filePath ?? "Click a finding row to preview code context."}
          </p>
          {finding?.commit && (
            <p
              className="mt-2 truncate font-[family-name:var(--font-jetbrains-mono)] text-xs text-[var(--color-text-secondary)]"
              title={finding.commit}
            >
              Evidence commit: <span className="text-[var(--color-text-primary)]">{finding.commit}</span>
            </p>
          )}
          {finding ? (
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-[var(--color-border)] px-2.5 py-1 text-xs font-medium text-[var(--color-text-secondary)]">
                {finding.detector}
              </span>
              <span className="rounded-full border border-[var(--color-border)] px-2.5 py-1 text-xs font-medium text-[var(--color-text-secondary)]">
                {finding.source}
              </span>
            </div>
          ) : null}
        </div>

        <div className="flex shrink-0 items-center gap-2">
          {finding && preview?.githubUrl ? (
            <a
              href={preview.githubUrl}
              target="_blank"
              rel="noreferrer"
              className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-accent)] hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-accent)]"
            >
              View in repository
            </a>
          ) : null}
          {finding ? (
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)]"
            >
              ✕ Close
            </button>
          ) : null}
        </div>
      </div>

      <div className="p-5">
        {!finding ? (
          <div className="flex min-h-[460px] items-center justify-center rounded-xl border border-dashed border-[var(--color-border)] px-6 text-center text-sm text-[var(--color-text-secondary)]">
            Select a finding to preview code.
          </div>
        ) : isLoading ? (
          <div className="flex min-h-[460px] items-center justify-center rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-6 text-sm text-[var(--color-text-secondary)]">
            Loading code preview...
          </div>
        ) : error ? (
          <div className="space-y-4">
            <div className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-900/20 dark:text-amber-200">
              <p className="font-medium">{error}</p>
            </div>
            <a
              href={`https://github.com/${finding.organization}/${finding.repository}/blob/${finding.commit ?? "HEAD"}/${finding.filePath ?? ""}${finding.line ? `#L${finding.line}` : ""}`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2 text-sm font-semibold text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)]"
            >
              View in repository
            </a>
          </div>
        ) : preview ? (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3 text-xs text-[var(--color-text-secondary)]">
              <div className="min-w-0 font-[family-name:var(--font-jetbrains-mono)]">
                <p className="truncate text-[var(--color-text-primary)]" title={preview.commit}>
                  commit {preview.commit}
                  {preview.commitIsHead && (
                    <span className="ml-2 text-amber-500">· HEAD (light scan — no commit recorded)</span>
                  )}
                </p>
                {preview.commitDate && (
                  <p className="mt-0.5 truncate text-[var(--color-text-secondary)]">
                    {new Date(preview.commitDate).toLocaleString(undefined, {
                      year: "numeric",
                      month: "short",
                      day: "numeric",
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </p>
                )}
                <p className="mt-0.5 truncate text-[var(--color-text-secondary)]" title={preview.filePath}>
                  {preview.filePath}
                  {preview.line ? ` : L${preview.line}` : ""}
                </p>
              </div>
            </div>
            <div className="max-h-[620px] overflow-auto rounded-2xl border border-[var(--color-border)] bg-slate-100 dark:bg-slate-950">
              <pre className="min-w-max p-4 text-sm leading-6 text-slate-700 dark:text-slate-300">
                <code>
                  {preview.lines.map((line) => (
                    <span
                      key={line.number}
                      className={`block ${line.highlighted ? "-mx-4 bg-orange-500/15 px-4 text-orange-700 dark:text-orange-100" : ""}`}
                    >
                      <span className="mr-5 inline-block w-12 select-none text-right text-[var(--color-text-secondary)]">
                        {line.number}
                      </span>
                      <span>{line.content || " "}</span>
                    </span>
                  ))}
                </code>
              </pre>
            </div>
          </div>
        ) : (
          <div className="flex min-h-[460px] items-center justify-center rounded-xl border border-dashed border-[var(--color-border)] px-6 text-center text-sm text-[var(--color-text-secondary)]">
            Select a finding to preview code.
          </div>
        )}

        <div className="px-5 pt-5">
          <DetectionHistoryPanel finding={finding} />
        </div>

        {finding && onReview ? (
          <div className="border-[var(--color-border)] p-5">
            <div className="mb-5 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--color-text-secondary)]">Key verdict</p>
                <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
                  Applies to all commits sharing this key value.
                </p>
              </div>
              <div className="mt-4 flex flex-wrap items-center gap-2">
                <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1 text-xs font-medium text-[var(--color-text-secondary)]">
                  {keyOccurrenceCount} occurrence{keyOccurrenceCount === 1 ? "" : "s"} with this key
                </span>
              </div>
              <div className="mt-4 flex flex-wrap gap-2">
                {canReview ? (
                  <ReviewActionButtons
                    currentStatus={finding.reviewStatus}
                    onConfirm={() => onReview("confirmed")}
                    onFalsePositive={() => onReview("false_positive")}
                    onActionTaken={() => onReview("action_taken")}
                    onReset={() => onReview("new")}
                    showReset
                  />
                ) : (
                  <p className="text-xs text-[var(--color-text-secondary)] italic">
                    Reviewing requires higher permissions.
                  </p>
                )}
              </div>
            </div>

            <div className="mb-5 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--color-text-secondary)]">Same key found at</p>
                  <p className="mt-1 text-xs text-[var(--color-text-secondary)]">Other raw scanner hits with the same detected key value.</p>
                </div>
                <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1 text-xs font-medium text-[var(--color-text-secondary)]">
                  {relatedFindings.length} related
                </span>
              </div>
              {relatedFindings.length === 0 ? (
                <p className="mt-3 text-xs text-[var(--color-text-secondary)]">No other matching key occurrences found.</p>
              ) : (
                <div className="mt-3 max-h-56 space-y-2 overflow-auto pr-1">
                  {relatedFindings.map((related, index) => {
                    const shortCommit = related.commit ? related.commit.slice(0, 7) : null
                    const location = related.filePath
                      ? `${related.filePath}${related.line ? `:${related.line}` : ""}`
                      : "Location unavailable"
                    return (
                      <button
                        key={`${findingUiIdentity(related)}::${index}`}
                        type="button"
                        onClick={() => onSelectRelated(related)}
                        className="w-full rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-3 text-left transition-colors hover:border-blue-300 hover:bg-blue-50/50 dark:hover:border-blue-700 dark:hover:bg-blue-950/20"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <p
                              className="truncate text-sm font-semibold text-[var(--color-text-primary)]"
                              title={`${related.organization}/${related.repository}`}
                            >
                              {related.organization}/{related.repository}
                            </p>
                            <p
                              className="mt-1 truncate font-[family-name:var(--font-jetbrains-mono)] text-xs text-[var(--color-text-secondary)]"
                              title={location}
                            >
                              {location}
                            </p>
                          </div>
                          <span className={`shrink-0 rounded-full border px-2 py-0.5 text-xs font-medium ${reviewTone(related.reviewStatus)}`}>
                            {reviewStatusLabel(related.reviewStatus)}
                          </span>
                        </div>
                        <div className="mt-2 flex flex-wrap gap-2 text-xs text-[var(--color-text-secondary)]">
                          {shortCommit ? (
                            <span className="rounded-full bg-[var(--color-surface-raised)] px-2 py-0.5 font-[family-name:var(--font-jetbrains-mono)]">
                              {shortCommit}
                            </span>
                          ) : null}
                          <span className="rounded-full bg-[var(--color-surface-raised)] px-2 py-0.5">{related.source}</span>
                          <span className="rounded-full bg-[var(--color-surface-raised)] px-2 py-0.5">{related.detector}</span>
                        </div>
                      </button>
                    )
                  })}
                </div>
              )}
            </div>

            <details
              className="mb-5 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4"
              open={evidenceValue.length < 120 ? true : undefined}
            >
              <summary className="cursor-pointer list-none">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--color-text-secondary)]">Scanner evidence</p>
                    <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
                      Candidate value reported by the scanner, not a final verdict.
                    </p>
                  </div>
                  <span className={`rounded-full border px-2.5 py-1 text-xs font-medium ${reviewTone(finding.reviewStatus)}`}>
                    {reviewStatusLabel(finding.reviewStatus)}
                  </span>
                </div>
              </summary>
              <p
                className="mt-3 break-all font-[family-name:var(--font-jetbrains-mono)] text-sm text-[var(--color-text-primary)]"
                title={evidenceValue}
              >
                {evidenceValue}
              </p>
              <div className="mt-3 flex flex-wrap gap-2 text-xs text-[var(--color-text-secondary)]">
                <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1">
                  detector: {finding.detector}
                </span>
                <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1">
                  source: {finding.source}
                </span>
              </div>
            </details>
          </div>
        ) : null}
      </div>
    </FindingsDrawerShell>
  )
}
