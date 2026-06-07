"use client"

/**
 * "Recommended fix" block for the findings detail drawer.
 *
 * Returns null when the finding has no `recommendedFix` payload — callers do
 * not need to guard the section themselves. Copy snippet uses the local
 * Clipboard API and surfaces a transient "Copied" affordance for 1.5s.
 */

import { useCallback, useEffect, useRef, useState } from "react"

import type { FindingRecommendedFix } from "@/lib/shared/findings/row-mapper"

interface RecommendedFixSectionProps {
  fix: FindingRecommendedFix | undefined
  onViewDiff?: () => void
}

function buildTitle(fix: FindingRecommendedFix): string {
  if (fix.title) return fix.title
  const parts: string[] = ["Upgrade"]
  if (fix.packageName) parts.push(fix.packageName)
  if (fix.fromVersion && fix.toVersion) {
    parts.push(`from ${fix.fromVersion} to ${fix.toVersion}`)
  } else if (fix.toVersion) {
    parts.push(`to ${fix.toVersion}`)
  }
  return parts.join(" ")
}

function buildSnippet(fix: FindingRecommendedFix): string {
  if (fix.snippet) return fix.snippet
  if (fix.packageName && fix.toVersion) return `${fix.packageName}@${fix.toVersion}`
  if (fix.toVersion) return fix.toVersion
  return buildTitle(fix)
}

export function RecommendedFixSection({ fix, onViewDiff }: RecommendedFixSectionProps) {
  const [copied, setCopied] = useState(false)
  const timerRef = useRef<number | null>(null)

  useEffect(
    () => () => {
      if (timerRef.current != null) {
        window.clearTimeout(timerRef.current)
      }
    },
    [],
  )

  const handleCopy = useCallback(async () => {
    if (!fix) return
    const snippet = buildSnippet(fix)
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard) {
        await navigator.clipboard.writeText(snippet)
      }
      setCopied(true)
      if (timerRef.current != null) window.clearTimeout(timerRef.current)
      timerRef.current = window.setTimeout(() => setCopied(false), 1500)
    } catch (err) {
      // Failing loudly here would block the visual stub during local
      // development on browsers that gate clipboard access. Surface the
      // failure in the console without throwing.
      console.warn("[recommended-fix] clipboard write failed", err)
    }
  }, [fix])

  const handleViewDiff = useCallback(() => {
    if (onViewDiff) {
      onViewDiff()
      return
    }
    console.log("[recommended-fix] view-diff clicked")
  }, [onViewDiff])

  if (!fix) return null

  const title = buildTitle(fix)

  return (
    <section aria-labelledby="finding-recommended-fix-title">
      <h3
        id="finding-recommended-fix-title"
        className="text-base font-semibold text-[var(--color-text-primary)]"
      >
        Recommended fix
      </h3>

      <p className="mt-2 text-sm text-[var(--color-text-primary)]">{title}</p>

      {(fix.fromVersion || fix.toVersion) && (
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          {fix.packageName && (
            <span className="font-[family-name:var(--font-jetbrains-mono)]">
              {fix.packageName}{" "}
            </span>
          )}
          {fix.fromVersion && (
            <span className="font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-severity-critical)]">
              {fix.fromVersion}
            </span>
          )}
          {fix.fromVersion && fix.toVersion && (
            <span className="mx-1 text-[var(--color-text-tertiary)]">→</span>
          )}
          {fix.toVersion && (
            <span className="font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-severity-low)]">
              {fix.toVersion}
            </span>
          )}
        </p>
      )}

      {fix.description && (
        <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
          {fix.description}
        </p>
      )}

      <div className="mt-3 flex flex-wrap gap-2">
        <button
          type="button"
          onClick={handleCopy}
          aria-label="Copy upgrade snippet to clipboard"
          aria-live="polite"
          className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
        >
          {copied ? "Copied" : "Copy snippet"}
        </button>
        <button
          type="button"
          onClick={handleViewDiff}
          aria-label="View diff for the recommended fix"
          className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
        >
          View diff
        </button>
      </div>
    </section>
  )
}
