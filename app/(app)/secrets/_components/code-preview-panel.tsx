"use client"

import { useState, useEffect } from "react"
import type { CodePreviewResponse } from "@/lib/client/secrets/dashboard-client"
import { FindingsDrawerShell } from "@/components/shared/FindingsDrawerShell"
import { findingUiIdentity, reviewStatusLabel, reviewTone } from "@/lib/shared/secrets/dashboard-utils"
import type { SecretFinding, SecretReviewStatus } from "@/lib/shared/secrets/types"
import { ReviewActionButtons } from "@/app/(app)/secrets/_components/review-action-buttons"
import { DetectionHistoryPanel } from "@/app/(app)/secrets/_components/detection-history-panel"
import {
  DrawerHeader,
  DrawerSection,
  DrawerCodeBlock,
  DrawerFooter,
} from "@/components/shared/FindingDrawer"

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

  const [secretRevealed, setSecretRevealed] = useState(false)

  useEffect(() => {
    setSecretRevealed(false)
  }, [finding])

  return (
    <FindingsDrawerShell open={!!finding} onClose={onClose} label="Secret finding details">
      <DrawerHeader
        eyebrow={finding ? `Secrets · ${finding.detector}` : "Secrets"}
        title={finding ? `${finding.organization}/${finding.repository}` : "Select a finding"}
        identifier={finding?.filePath ?? undefined}
        repoUrl={preview?.githubUrl ?? undefined}
        onClose={onClose}
        badges={finding ? (
          <>
            <span className="rounded-full border border-[var(--color-border)] px-2.5 py-1 text-xs font-medium text-[var(--color-text-secondary)]">
              {finding.detector}
            </span>
            <span className="rounded-full border border-[var(--color-border)] px-2.5 py-1 text-xs font-medium text-[var(--color-text-secondary)]">
              {finding.source}
            </span>
          </>
        ) : undefined}
      />

      <div className="flex-1 overflow-y-auto p-5 space-y-5">
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
          <DrawerCodeBlock
            lines={preview.lines}
            label={`commit ${preview.commit}${preview.commitIsHead ? " · HEAD" : ""}`}
            filePath={`${preview.filePath}${preview.line ? ` : L${preview.line}` : ""}`}
          />
        ) : (
          <div className="flex min-h-[200px] items-center justify-center rounded-xl border border-dashed border-[var(--color-border)] px-6 text-center text-sm text-[var(--color-text-secondary)]">
            Select a finding to preview code.
          </div>
        )}

        <DrawerSection label="Detection history">
          <DetectionHistoryPanel finding={finding} />
        </DrawerSection>

        {/* Same key found at — always shown when finding exists */}
        {finding && (
          <DrawerSection label="Same key found at">
            <div className="flex flex-wrap items-center justify-between gap-2 pb-2">
              <p className="text-xs text-[var(--color-text-secondary)]">
                Other raw scanner hits with the same detected key value.
              </p>
              <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1 text-xs font-medium text-[var(--color-text-secondary)]">
                {relatedFindings.length} related
              </span>
            </div>
            {relatedFindings.length === 0 ? (
              <p className="text-xs text-[var(--color-text-secondary)]">No other matching key occurrences found.</p>
            ) : (
              <div className="max-h-56 space-y-2 overflow-auto pr-1">
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
                      className="w-full rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-3 text-left transition-colors hover:border-[var(--color-accent)]/30 hover:bg-[var(--color-accent)]/5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <p className="truncate text-sm font-semibold text-[var(--color-text-primary)]" title={`${related.organization}/${related.repository}`}>
                            {related.organization}/{related.repository}
                          </p>
                          <p className="mt-1 truncate font-[family-name:var(--font-jetbrains-mono)] text-xs text-[var(--color-text-secondary)]" title={location}>
                            {location}
                          </p>
                        </div>
                        <span className={`shrink-0 rounded-full border px-2 py-0.5 text-xs font-medium ${reviewTone(related.reviewStatus)}`}>
                          {reviewStatusLabel(related.reviewStatus)}
                        </span>
                      </div>
                      <div className="mt-2 flex flex-wrap gap-2 text-xs text-[var(--color-text-secondary)]">
                        {shortCommit && (
                          <span className="rounded-full bg-[var(--color-surface-raised)] px-2 py-0.5 font-[family-name:var(--font-jetbrains-mono)]">
                            {shortCommit}
                          </span>
                        )}
                        <span className="rounded-full bg-[var(--color-surface-raised)] px-2 py-0.5">{related.source}</span>
                        <span className="rounded-full bg-[var(--color-surface-raised)] px-2 py-0.5">{related.detector}</span>
                      </div>
                    </button>
                  )
                })}
              </div>
            )}
          </DrawerSection>
        )}

        {/* Scanner evidence — always shown when finding exists */}
        {finding && (
          <DrawerSection label="Scanner evidence">
            <p className="text-xs text-[var(--color-text-secondary)]">
              Candidate value reported by the scanner, not a final verdict.
            </p>
            <div className="flex items-center justify-between gap-3">
              <p
                className="break-all font-[family-name:var(--font-jetbrains-mono)] text-sm text-[var(--color-text-primary)]"
                title={secretRevealed ? evidenceValue : undefined}
              >
                {secretRevealed ? evidenceValue : "••••••••••••••••••••"}
              </p>
              <button
                type="button"
                aria-pressed={secretRevealed}
                onClick={() => setSecretRevealed((v) => !v)}
                className="shrink-0 rounded-lg border border-[var(--color-border)] px-3 py-2 text-xs font-semibold text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
              >
                {secretRevealed ? "Hide value" : "Reveal value"}
              </button>
            </div>
            {!secretRevealed && (
              <p className="mt-2 text-[11px] text-[var(--color-text-secondary)]">
                This value will be visible on screen when revealed.
              </p>
            )}
            <div className="mt-3 flex flex-wrap gap-2 text-xs text-[var(--color-text-secondary)]">
              <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1">
                detector: {finding.detector}
              </span>
              <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1">
                source: {finding.source}
              </span>
            </div>
          </DrawerSection>
        )}
      </div>

      {finding && onReview && (
        <DrawerFooter>
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)]">
              Key verdict
            </p>
            <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
              Applies to all {keyOccurrenceCount} occurrence{keyOccurrenceCount === 1 ? "" : "s"} of this key.
            </p>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
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
              <p className="text-xs italic text-[var(--color-text-secondary)]">
                Reviewing requires higher permissions.
              </p>
            )}
          </div>
        </DrawerFooter>
      )}
    </FindingsDrawerShell>
  )
}
