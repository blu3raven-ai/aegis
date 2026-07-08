"use client"

/**
 * "Code preview" block for the findings detail drawer.
 *
 * Renders the short, client-safe snippet the backend supplies. Code findings
 * show the surrounding window with the offending line(s) highlighted and the
 * gutter anchored to the real file line, so a triager can see *where* the issue
 * is; the inline view auto-scrolls to centre the highlighted line and "Expand"
 * opens the full window in a wide sheet. When no snippet was captured, a small
 * empty state names the location instead of rendering nothing.
 *
 * Secrets render as a single masked value with an eye toggle that fetches the
 * raw value on demand — the plaintext secret is never in the list/detail
 * payload; the reveal is permission-gated and audited server side, and the
 * revealed value lives only in local state (dropped on unmount).
 */

import { useCallback, useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/Button"
import { LinkButton } from "@/components/ui/LinkButton"
import { Sheet } from "@/components/ui/Sheet"
import { cn } from "@/lib/shared/utils"
import { revealSecretValue } from "@/lib/client/findings-api"
import { useHasPermission } from "@/lib/client/use-permission"

interface CodePreviewSectionProps {
  snippet: string | undefined
  /** Repo-relative location shown as the caption, e.g. "src/server.py:93". */
  filePath?: string
  /** When set, enables the eye toggle that reveals this secret's raw value. */
  secretFindingId?: string
  /** 1-indexed file line of the snippet's first line (gutter anchor). */
  startLine?: number
  /** Offending line range to highlight within the snippet. */
  highlightStart?: number
  highlightEnd?: number
  /** Render an explanatory empty state (with the location) when no snippet. */
  showEmptyWhenMissing?: boolean
  /** The drawer is still fetching detail — show a skeleton, not the empty state. */
  detailLoading?: boolean
  /** SCM web URL for this finding's location; renders a "View in repository" link when set. */
  repoUrl?: string | null
  /** Scanner that produced the finding — tailors the missing-snippet copy honestly. */
  scanner?: string
}

/** First line number from a "path:line" location — fallback gutter anchor. */
function parseStartLine(filePath: string | undefined): number | null {
  const match = filePath?.match(/:(\d+)$/)
  if (!match) return null
  const n = Number(match[1])
  return Number.isFinite(n) && n > 0 ? n : null
}

/** Strip the indentation shared by every non-empty line. */
function dedent(text: string): string {
  const lines = text.split("\n")
  let min = Infinity
  for (const line of lines) {
    if (!line.trim()) continue
    min = Math.min(min, line.match(/^[ \t]*/)?.[0].length ?? 0)
  }
  if (!Number.isFinite(min) || min === 0) return text
  return lines.map((line) => line.slice(min)).join("\n")
}

function EyeIcon({ off }: { off?: boolean }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className="h-3.5 w-3.5">
      <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" />
      <circle cx="12" cy="12" r="3" />
      {off && <path d="M3 3l18 18" />}
    </svg>
  )
}

function ExpandIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className="h-3.5 w-3.5">
      <path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7" />
    </svg>
  )
}

function ExternalLinkIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className="h-3.5 w-3.5">
      <path d="M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
    </svg>
  )
}

/** Opens the finding's file in its source repository, in a new tab. */
function ViewInRepoButton({ url }: { url: string }) {
  return (
    <LinkButton
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      variant="secondary"
      size="xs"
      trailingIcon={<ExternalLinkIcon />}
    >
      View in repository
    </LinkButton>
  )
}

/** Line-numbered code body with the offending range highlighted. */
function CodeLines({
  lines,
  startLine,
  showGutter,
  highlightStart,
  highlightEnd,
  firstHighlightRef,
  blurHighlighted = false,
}: {
  lines: string[]
  startLine: number | null
  showGutter: boolean
  highlightStart?: number
  highlightEnd?: number
  firstHighlightRef?: React.Ref<HTMLSpanElement>
  /** Blur the highlighted line's content (secret preview: hide the value until revealed). */
  blurHighlighted?: boolean
}) {
  const base = startLine ?? 1
  const hlEnd = highlightEnd ?? highlightStart
  return (
    <code className="block font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-primary)]">
      {lines.map((line, i) => {
        const lineNo = base + i
        const highlighted =
          highlightStart != null && lineNo >= highlightStart && lineNo <= (hlEnd ?? highlightStart)
        const isFirstHighlight = highlighted && lineNo === highlightStart
        return (
          <span
            key={i}
            ref={isFirstHighlight ? firstHighlightRef : undefined}
            className={cn(
              showGutter ? "grid grid-cols-[2.5rem_1fr] gap-3" : "block",
              highlighted &&
                "rounded-sm bg-[color-mix(in_srgb,var(--color-severity-high)_15%,transparent)] shadow-[inset_2px_0_0_var(--color-severity-high)]",
            )}
          >
            {showGutter && (
              <span
                aria-hidden={!highlighted}
                className={cn(
                  "select-none text-right tabular-nums",
                  highlighted ? "font-semibold text-[var(--color-severity-high-text)]" : "text-[var(--color-text-tertiary)]",
                )}
              >
                {lineNo}
              </span>
            )}
            {highlighted && <span className="sr-only">Flagged line {lineNo}: </span>}
            <span
              className={cn(
                "whitespace-pre",
                highlighted && blurHighlighted && "select-none blur-[5px]",
              )}
              title={highlighted && blurHighlighted ? "Hidden — use Reveal to view the secret" : undefined}
            >
              {line || " "}
            </span>
          </span>
        )
      })}
    </code>
  )
}

export function CodePreviewSection({
  snippet,
  filePath,
  secretFindingId,
  startLine,
  highlightStart,
  highlightEnd,
  showEmptyWhenMissing,
  detailLoading,
  repoUrl,
  scanner,
}: CodePreviewSectionProps) {
  const isSecret = Boolean(secretFindingId)
  // Revealing the raw secret is gated on the same workspace permission the
  // backend enforces (reveal_secret — a dedicated, more-sensitive grant than
  // triage; review_findings does NOT imply it). Without it, the reveal
  // affordance is hidden entirely — the redacted window still shows, the value
  // just can't be unmasked. The server re-checks on every reveal; this only
  // hides the button.
  const { allowed: canReveal } = useHasPermission("reveal_secret")
  const [copied, setCopied] = useState(false)
  const [revealed, setRevealed] = useState(false)
  const [rawValue, setRawValue] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState(false)
  const timerRef = useRef<number | null>(null)
  const preRef = useRef<HTMLPreElement>(null)
  const hlRef = useRef<HTMLSpanElement>(null)

  useEffect(() => {
    setRevealed(false)
    setRawValue(null)
    setError(null)
    setExpanded(false)
  }, [secretFindingId, snippet])

  useEffect(
    () => () => {
      if (timerRef.current != null) window.clearTimeout(timerRef.current)
    },
    [],
  )

  const trimmed = snippet?.replace(/\s+$/, "")
  const shown = revealed && rawValue != null ? rawValue : trimmed ?? ""
  const display = isSecret ? shown : dedent(shown)
  const lines = display.split("\n")
  // A secret with a real (multi-line) redacted window shows it in file context
  // with the offending line highlighted, exactly like other findings. The bare
  // masked value and the revealed raw value stay a plain block — there's no
  // surrounding code to number or anchor a highlight against.
  const secretShowsWindow = isSecret && !revealed && lines.length > 1
  const useCodeLines = !isSecret || secretShowsWindow
  const anchor = useCodeLines ? startLine ?? parseStartLine(filePath) : null
  const showGutter = useCodeLines && (lines.length > 1 || anchor != null)
  // Blur the flagged line's value until the analyst explicitly reveals it, so
  // the full secret isn't shoulder-surfable in the window view.
  const blurHighlighted = isSecret && !revealed

  // Centre the highlighted line within the height-capped inline view.
  useEffect(() => {
    const pre = preRef.current
    const hl = hlRef.current
    if (pre && hl) {
      pre.scrollTop = Math.max(0, hl.offsetTop - pre.clientHeight / 2 + hl.clientHeight / 2)
    }
  }, [display, anchor, highlightStart])

  const handleToggleReveal = useCallback(async () => {
    if (!secretFindingId) return
    if (revealed) {
      setRevealed(false)
      return
    }
    if (rawValue != null) {
      setRevealed(true)
      return
    }
    setLoading(true)
    setError(null)
    try {
      const value = await revealSecretValue(secretFindingId)
      setRawValue(value)
      setRevealed(true)
    } catch {
      setError("Couldn't reveal — you may not have permission.")
    } finally {
      setLoading(false)
    }
  }, [secretFindingId, revealed, rawValue])

  const handleCopy = useCallback(async () => {
    if (!display) return
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard) {
        await navigator.clipboard.writeText(display)
      }
      setCopied(true)
      if (timerRef.current != null) window.clearTimeout(timerRef.current)
      timerRef.current = window.setTimeout(() => setCopied(false), 1500)
    } catch (err) {
      console.warn("[code-preview] clipboard write failed", err)
    }
  }, [display])

  // Secrets always render the section (location + masked value + Reveal), even
  // when no redacted value was stored — the analyst can still see where it is
  // and reveal the value on demand.
  if (!trimmed && !isSecret) {
    if (detailLoading) {
      // Detail is still fetching — a code-block skeleton, not the "no code"
      // CTA, which would otherwise flash on every code finding before the
      // snippet arrives (and on each prev/next step).
      return (
        <section aria-labelledby="finding-code-preview-title">
          <h3 id="finding-code-preview-title" className="text-base font-semibold text-[var(--color-text-primary)]">
            Code preview
          </h3>
          <div className="mt-2 space-y-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-section)] p-4">
            {[88, 64, 76, 48, 70].map((w, i) => (
              <div
                key={i}
                className="h-3 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse"
                style={{ width: `${w}%` }}
                aria-hidden="true"
              />
            ))}
          </div>
        </section>
      )
    }
    // Findings whose vulnerability has no line in the user's code: container
    // image packages, and transitive deps (not declared in any manifest). For
    // these, promising "re-run to capture the code" would be dishonest — there
    // is no source site to capture. Everything else with a location just failed
    // to capture a window (unreadable source), which a re-run can fix.
    const noSourceSite =
      scanner === "container_scanning" || (scanner === "dependencies_scanning" && !filePath)
    if (showEmptyWhenMissing && (filePath || noSourceSite)) {
      const message = noSourceSite
        ? scanner === "container_scanning"
          ? "No source to preview — this vulnerability comes from a package in the container image, not a line in your code."
          : "No source to preview — this transitive dependency isn't declared in your manifests, so there's no line to point at."
        : "We couldn't capture the surrounding code for this location. The source may not have been readable during the scan — re-run it to pull in the lines."
      return (
        <section aria-labelledby="finding-code-preview-title">
          <h3 id="finding-code-preview-title" className="text-base font-semibold text-[var(--color-text-primary)]">
            Code preview
          </h3>
          <div className="mt-2 rounded-lg border border-dashed border-[var(--color-border)] bg-[var(--color-bg-section)] p-4 text-center">
            {filePath && (
              <p className="truncate font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-tertiary)]" title={filePath}>
                {filePath}
              </p>
            )}
            <p className={cn("text-xs text-[var(--color-text-secondary)]", filePath && "mt-1")}>
              {message}
            </p>
            {repoUrl && (
              <div className="mt-3 flex justify-center">
                <ViewInRepoButton url={repoUrl} />
              </div>
            )}
          </div>
        </section>
      )
    }
    return null
  }

  return (
    <section aria-labelledby="finding-code-preview-title">
      <div className="flex items-center justify-between gap-3">
        <h3
          id="finding-code-preview-title"
          className="text-base font-semibold text-[var(--color-text-primary)]"
        >
          {isSecret ? "Secret" : "Code preview"}
        </h3>
        <div className="flex items-center gap-2">
          {/* Prefer a deep-link to the file in its repository; fall back to the
              in-app full-window view only when no repo URL resolves. */}
          {repoUrl ? (
            <ViewInRepoButton url={repoUrl} />
          ) : (
            !isSecret && (
              <Button
                variant="secondary"
                size="xs"
                onClick={() => setExpanded(true)}
                leadingIcon={<ExpandIcon />}
                aria-label="Expand code preview"
              >
                Expand
              </Button>
            )
          )}
          {isSecret && canReveal && (
            <Button
              variant="secondary"
              size="xs"
              onClick={handleToggleReveal}
              isLoading={loading}
              leadingIcon={<EyeIcon off={revealed} />}
              aria-label={revealed ? "Hide secret value" : "Reveal secret value"}
            >
              {revealed ? "Hide" : "Reveal"}
            </Button>
          )}
          <Button
            variant="secondary"
            size="xs"
            onClick={handleCopy}
            aria-label="Copy to clipboard"
            aria-live="polite"
          >
            {copied ? "Copied" : "Copy"}
          </Button>
        </div>
      </div>

      {filePath && (
        <p className="mt-1 truncate font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-tertiary)]" title={filePath}>
          {filePath}
        </p>
      )}

      {useCodeLines ? (
        <div className="mt-2 overflow-hidden rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-section)]">
          <pre ref={preRef} className="relative max-h-72 overflow-auto p-3 text-[12px] leading-relaxed">
            <CodeLines
              lines={lines}
              startLine={anchor}
              showGutter={showGutter}
              highlightStart={highlightStart}
              highlightEnd={highlightEnd}
              firstHighlightRef={hlRef}
              blurHighlighted={blurHighlighted}
            />
          </pre>
        </div>
      ) : (
        <div className="mt-2 overflow-x-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-section)] px-3 py-2">
          <code
            className={cn(
              "whitespace-pre font-[family-name:var(--font-jetbrains-mono)] text-[13px]",
              display ? "text-[var(--color-text-primary)]" : "text-[var(--color-text-tertiary)]",
            )}
          >
            {display || (canReveal ? "•••••••••••• (hidden — Reveal to view)" : "•••••••••••• (hidden)")}
          </code>
        </div>
      )}

      {isSecret && revealed && (
        <p className="mt-1.5 text-[11px] text-[var(--color-severity-medium-text)]">
          Showing the raw secret. This view is recorded in the audit log.
        </p>
      )}
      {error && (
        <p className="mt-1.5 text-[11px] text-[var(--color-severity-high-text)]" role="alert">
          {error}
        </p>
      )}

      {!isSecret && (
        <Sheet
          open={expanded}
          onClose={() => setExpanded(false)}
          title="Code preview"
          description={filePath}
          size="xl"
          footer={
            <div className="flex justify-end">
              <Button variant="secondary" size="sm" onClick={handleCopy} aria-live="polite">
                {copied ? "Copied" : "Copy"}
              </Button>
            </div>
          }
        >
          <div className="overflow-hidden rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-section)]">
            <pre className="overflow-x-auto p-4 text-[13px] leading-relaxed">
              <CodeLines
                lines={lines}
                startLine={anchor}
                showGutter={showGutter}
                highlightStart={highlightStart}
                highlightEnd={highlightEnd}
              />
            </pre>
          </div>
        </Sheet>
      )}
    </section>
  )
}
