"use client"

/**
 * "Recommended fix" block for the findings detail drawer.
 *
 * Branches on the fix `kind`: deps `upgrade` (also the default for payloads
 * without a kind), SAST `code_patch`, IaC `config_patch`, and secrets
 * `rotation`. Each kind renders the affordances that make sense for it — the
 * upgrade view stays a copyable snippet, rotation is a runbook with no single
 * apply step, and nothing here ever auto-applies a change.
 *
 * Returns null when the finding has no `recommendedFix` payload — callers do
 * not need to guard the section themselves. Copy buttons use the local
 * Clipboard API and surface a transient "Copied" affordance for 1.5s.
 */

import { useCallback, useEffect, useRef, useState } from "react"

import type {
  FindingRecommendedFix,
  FindingRecommendedFixStep,
} from "@/lib/shared/findings/row-mapper"
import { Button } from "@/components/ui/Button"
import { cn } from "@/lib/shared/utils"

interface RecommendedFixSectionProps {
  fix: FindingRecommendedFix | undefined
  onViewDiff?: () => void
}

const SOURCE_LABEL: Record<NonNullable<FindingRecommendedFix["source"]>, string> = {
  synthesized: "Synthesized",
  deterministic: "Deterministic",
  llm: "Argus",
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

function CheckIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className="h-3 w-3">
      <path d="M20 6 9 17l-5-5" />
    </svg>
  )
}

function ExternalLinkIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className="h-3 w-3">
      <path d="M15 3h6v6M10 14 21 3M21 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5" />
    </svg>
  )
}

/** Secondary-styled copy button that owns its own transient "Copied" state. */
function CopyButton({
  value,
  idleLabel,
  ariaLabel,
  size = "sm",
}: {
  value: string
  idleLabel: string
  ariaLabel: string
  size?: "xs" | "sm"
}) {
  const [copied, setCopied] = useState(false)
  const timerRef = useRef<number | null>(null)

  useEffect(
    () => () => {
      if (timerRef.current != null) window.clearTimeout(timerRef.current)
    },
    [],
  )

  const handleCopy = useCallback(async () => {
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard) {
        await navigator.clipboard.writeText(value)
      }
      setCopied(true)
      if (timerRef.current != null) window.clearTimeout(timerRef.current)
      timerRef.current = window.setTimeout(() => setCopied(false), 1500)
    } catch (err) {
      // Failing loudly here would block the drawer on browsers that gate
      // clipboard access; surface it in the console without throwing.
      console.warn("[recommended-fix] clipboard write failed", err)
    }
  }, [value])

  return (
    <Button
      variant="secondary"
      size={size}
      onClick={handleCopy}
      aria-label={ariaLabel}
      aria-live="polite"
    >
      {copied ? "Copied" : idleLabel}
    </Button>
  )
}

function ExternalLink({
  href,
  children,
  ariaLabel,
}: {
  href: string
  children: string
  ariaLabel?: string
}) {
  // href here is server-supplied (rotation step.url / code_patch diffUrl) and can
  // be verifier-influenced — only render a live link for http(s) so a javascript:
  // URL can't execute on click. Anything else renders as inert text.
  const safe = /^https?:\/\//i.test(href.trim()) ? href.trim() : null
  if (!safe) {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-[var(--color-text-tertiary)]">
        {children}
      </span>
    )
  }
  return (
    <a
      href={safe}
      target="_blank"
      rel="noopener noreferrer"
      aria-label={ariaLabel}
      className="inline-flex items-center gap-1 text-xs font-medium text-[var(--color-accent)] hover:underline"
    >
      {children}
      <ExternalLinkIcon />
    </a>
  )
}

/** Plain mono code block, matching the drawer's code-preview chrome. */
function CodeBlock({ children }: { children: string }) {
  return (
    <div className="overflow-hidden rounded-md border border-[var(--color-border)] bg-[var(--color-bg-section)]">
      <pre className="overflow-x-auto p-3 text-[12px] leading-relaxed">
        <code className="block whitespace-pre font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-primary)]">
          {children}
        </code>
      </pre>
    </div>
  )
}

function diffLineClass(line: string): string {
  if (line.startsWith("+") && !line.startsWith("+++")) return "text-[var(--color-severity-low-text)]"
  if (line.startsWith("-") && !line.startsWith("---")) return "text-[var(--color-severity-critical-text)]"
  if (line.startsWith("@@")) return "text-[var(--color-text-tertiary)]"
  return "text-[var(--color-text-primary)]"
}

/** Unified-diff renderer with add/remove line tinting. */
function DiffBlock({ diff }: { diff: string }) {
  const lines = diff.replace(/\n$/, "").split("\n")
  return (
    <div className="overflow-hidden rounded-md border border-[var(--color-border)] bg-[var(--color-bg-section)]">
      <pre className="overflow-x-auto p-3 text-[12px] leading-relaxed" aria-label="Unified diff">
        <code className="block font-[family-name:var(--font-jetbrains-mono)]">
          {lines.map((line, i) => (
            <span key={i} className={cn("block whitespace-pre", diffLineClass(line))}>
              {line || " "}
            </span>
          ))}
        </code>
      </pre>
    </div>
  )
}

/** Small "<source> · <confidence>" + validated caption, shown when present. */
function ProvenanceCaption({ fix }: { fix: FindingRecommendedFix }) {
  const meta: string[] = []
  if (fix.source) meta.push(SOURCE_LABEL[fix.source])
  if (fix.confidence) meta.push(`${fix.confidence} confidence`)
  if (!fix.rationale && meta.length === 0 && !fix.validated) return null
  return (
    <div className="mt-3">
      {fix.rationale && (
        <p className="text-xs text-[var(--color-text-secondary)]">{fix.rationale}</p>
      )}
      {(meta.length > 0 || fix.validated) && (
        <p className="mt-1 flex flex-wrap items-center gap-2 font-mono text-2xs uppercase tracking-[0.08em] text-[var(--color-text-tertiary)]">
          {meta.length > 0 && <span>{meta.join(" · ")}</span>}
          {fix.validated && (
            <span className="inline-flex items-center gap-1 text-[var(--color-severity-low-text)]">
              <CheckIcon /> Validated
            </span>
          )}
        </p>
      )}
    </div>
  )
}

/** deps `upgrade` — the original, regression-sensitive rendering. */
function UpgradeBody({
  fix,
  onViewDiff,
}: {
  fix: FindingRecommendedFix
  onViewDiff?: () => void
}) {
  const title = buildTitle(fix)
  return (
    <>
      <p className="mt-2 text-sm text-[var(--color-text-primary)]">{title}</p>

      {(fix.fromVersion || fix.toVersion) && (
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          {fix.packageName && (
            <span className="font-[family-name:var(--font-jetbrains-mono)]">
              {fix.packageName}{" "}
            </span>
          )}
          {fix.fromVersion && (
            <span className="font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-severity-critical-text)]">
              {fix.fromVersion}
            </span>
          )}
          {fix.fromVersion && fix.toVersion && (
            <span className="mx-1 text-[var(--color-text-tertiary)]">→</span>
          )}
          {fix.toVersion && (
            <span className="font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-severity-low-text)]">
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
        <CopyButton
          value={buildSnippet(fix)}
          idleLabel="Copy snippet"
          ariaLabel="Copy upgrade snippet to clipboard"
        />
        {onViewDiff && (
          <Button
            variant="secondary"
            size="sm"
            onClick={onViewDiff}
            aria-label="View diff for the recommended fix"
          >
            View diff
          </Button>
        )}
      </div>
    </>
  )
}

/** IaC `config_patch` — resource header + before/after code blocks. */
function ConfigPatchBody({ fix }: { fix: FindingRecommendedFix }) {
  return (
    <div className="mt-2">
      {(fix.resource || fix.filePath) && (
        <p className="text-sm text-[var(--color-text-secondary)]">
          {fix.resource && (
            <span className="font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-primary)]">
              {fix.resource}
            </span>
          )}
          {fix.resource && fix.filePath && (
            <span className="mx-1.5 text-[var(--color-text-tertiary)]">·</span>
          )}
          {fix.filePath && (
            <span className="font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-tertiary)]">
              {fix.filePath}
            </span>
          )}
        </p>
      )}

      {fix.description && (
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">{fix.description}</p>
      )}

      <div className="mt-2 grid gap-3 md:grid-cols-2">
        {fix.before != null && (
          <div>
            <p className="mb-1 font-mono text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
              Before
            </p>
            <CodeBlock>{fix.before}</CodeBlock>
          </div>
        )}
        {fix.after != null && (
          <div>
            <p className="mb-1 font-mono text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
              After
            </p>
            <CodeBlock>{fix.after}</CodeBlock>
          </div>
        )}
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-3">
        {fix.after != null && (
          <CopyButton
            value={fix.after}
            idleLabel="Copy change"
            ariaLabel="Copy the suggested configuration to clipboard"
          />
        )}
        <p className="text-xs text-[var(--color-text-tertiary)]">
          Suggested change. Review before applying.
        </p>
      </div>
    </div>
  )
}

/** SAST `code_patch` — unified diff with a file header. */
function CodePatchBody({
  fix,
  onViewDiff,
}: {
  fix: FindingRecommendedFix
  onViewDiff?: () => void
}) {
  const lineRange =
    fix.startLine != null
      ? `:${fix.startLine}${
          fix.endLine != null && fix.endLine !== fix.startLine ? `-${fix.endLine}` : ""
        }`
      : ""
  return (
    <div className="mt-2">
      {fix.title && (
        <p className="text-sm text-[var(--color-text-primary)]">{fix.title}</p>
      )}

      {fix.filePath && (
        <p
          className="mt-1 truncate font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-tertiary)]"
          title={fix.filePath}
        >
          {fix.filePath}
          {lineRange}
        </p>
      )}

      {fix.description && (
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">{fix.description}</p>
      )}

      {fix.diff && (
        <div className="mt-2">
          <DiffBlock diff={fix.diff} />
        </div>
      )}

      {(onViewDiff || fix.diffUrl) && (
        <div className="mt-3 flex flex-wrap items-center gap-3">
          {onViewDiff ? (
            <Button
              variant="secondary"
              size="sm"
              onClick={onViewDiff}
              aria-label="View diff for the recommended fix"
            >
              View diff
            </Button>
          ) : (
            fix.diffUrl && (
              <ExternalLink href={fix.diffUrl} ariaLabel="View diff for the recommended fix">
                View diff
              </ExternalLink>
            )
          )}
        </div>
      )}
    </div>
  )
}

function RotationStep({ step }: { step: FindingRecommendedFixStep }) {
  return (
    <li className="flex gap-3 rounded-md border border-[var(--color-border)] bg-[var(--color-bg-section)] p-3">
      <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-[var(--color-surface-raised)] text-2xs font-semibold tabular-nums text-[var(--color-text-secondary)]">
        {step.order}
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm text-[var(--color-text-primary)]">
          {step.label}
          {step.destructive && (
            <span className="ml-2 inline-flex items-center rounded-sm bg-[color-mix(in_srgb,var(--color-severity-critical)_14%,transparent)] px-1.5 py-0.5 text-2xs font-semibold uppercase tracking-[0.08em] text-[var(--color-severity-critical-text)]">
              Destructive
            </span>
          )}
        </p>
        {step.detail && (
          <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">{step.detail}</p>
        )}
        {step.cli && (
          <div className="mt-2">
            <CodeBlock>{step.cli}</CodeBlock>
          </div>
        )}
        {(step.url || step.cli) && (
          <div className="mt-2 flex flex-wrap items-center gap-3">
            {step.url && (
              <ExternalLink href={step.url} ariaLabel={`Open console for step ${step.order}`}>
                Open console
              </ExternalLink>
            )}
            {step.cli && (
              <CopyButton
                value={step.cli}
                idleLabel="Copy CLI"
                ariaLabel={`Copy CLI for step ${step.order}`}
                size="xs"
              />
            )}
          </div>
        )}
      </div>
    </li>
  )
}

/** secrets `rotation` — an ordered runbook; deletion alone is not remediation. */
function RotationBody({ fix }: { fix: FindingRecommendedFix }) {
  const steps = [...(fix.steps ?? [])].sort((a, b) => a.order - b.order)
  return (
    <div className="mt-2">
      {fix.title && (
        <p className="text-sm text-[var(--color-text-primary)]">{fix.title}</p>
      )}

      {(fix.provider || fix.verifiedActive) && (
        <div className="mt-1 flex flex-wrap items-center gap-2">
          {fix.provider && (
            <span className="font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-tertiary)]">
              {fix.provider}
            </span>
          )}
          {fix.verifiedActive && (
            <span className="inline-flex items-center gap-1 rounded-full border border-[color-mix(in_srgb,var(--color-severity-high)_40%,transparent)] bg-[color-mix(in_srgb,var(--color-severity-high)_12%,transparent)] px-2 py-0.5 text-2xs font-semibold uppercase tracking-[0.08em] text-[var(--color-severity-high-text)]">
              Verified active
            </span>
          )}
        </div>
      )}

      {fix.description && (
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">{fix.description}</p>
      )}

      {steps.length > 0 && (
        <ol className="mt-3 space-y-2">
          {steps.map((step) => (
            <RotationStep key={step.order} step={step} />
          ))}
        </ol>
      )}

      <p className="mt-3 text-xs text-[var(--color-severity-medium-text)]">
        Removing the secret from code does not remediate it. The live credential must be
        revoked and rotated.
      </p>
    </div>
  )
}

/** Fallback for an unrecognised kind — render whatever title/description exist. */
function GenericBody({ fix }: { fix: FindingRecommendedFix }) {
  return (
    <>
      {fix.title && (
        <p className="mt-2 text-sm text-[var(--color-text-primary)]">{fix.title}</p>
      )}
      {fix.description && (
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">{fix.description}</p>
      )}
    </>
  )
}

export function RecommendedFixSection({ fix, onViewDiff }: RecommendedFixSectionProps) {
  if (!fix) return null

  const kind = fix.kind

  return (
    <section aria-labelledby="finding-recommended-fix-title">
      <h3
        id="finding-recommended-fix-title"
        className="text-base font-semibold text-[var(--color-text-primary)]"
      >
        Recommended fix
      </h3>

      {kind === "config_patch" ? (
        <ConfigPatchBody fix={fix} />
      ) : kind === "rotation" ? (
        <RotationBody fix={fix} />
      ) : kind === "code_patch" ? (
        <CodePatchBody fix={fix} onViewDiff={onViewDiff} />
      ) : kind === "upgrade" || kind === undefined ? (
        <UpgradeBody fix={fix} onViewDiff={onViewDiff} />
      ) : (
        <GenericBody fix={fix} />
      )}

      <ProvenanceCaption fix={fix} />
    </section>
  )
}
