"use client"

import { useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/Button"
import { Textarea } from "@/components/ui/Textarea"
import { SegmentedControl } from "@/components/ui/SegmentedControl"
import { useHasPermission } from "@/lib/client/use-permission"
import { createAcceptedRisk, deleteAcceptedRisk } from "@/lib/client/accepted-risks-api"
import type { FindingRow } from "@/lib/shared/findings/row-mapper"

type Scope = "rule" | "file"

// Plain-language names for how wide the risk acceptance reaches.
const SCOPE_LABEL: Record<Scope, string> = {
  rule: "This rule, repo-wide",
  file: "Just this file",
}

/**
 * Disposition control for a ground-truth carve-out, rendered as a popover in the
 * finding action bar next to Defer/Dismiss. Declares the finding's behavior as
 * intended-by-design so matching findings are ruled out on the next scan. The
 * scope choice picks which key the carve-out matches on; a carve-out that would
 * match on nothing (asset only) is never submitted.
 */
export function FindingAcceptRiskAction({ finding }: { finding: FindingRow }) {
  const { allowed } = useHasPermission("manage_sources")
  const ruleKey = finding.ruleId ?? finding.rule ?? null
  const fileKey = finding.filePath ?? null
  const [open, setOpen] = useState(false)
  const [statement, setStatement] = useState("")
  const [scope, setScope] = useState<Scope>(ruleKey ? "rule" : "file")
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)
  // Id of the carve-out just created, so the inline Undo can delete it.
  const [createdId, setCreatedId] = useState<number | null>(null)
  const [undoing, setUndoing] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)

  // Close on outside click. Ref the outer container so re-clicking the trigger
  // to toggle-close isn't misread as an outside click.
  useEffect(() => {
    if (!open) return
    const onMouseDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener("mousedown", onMouseDown)
    return () => document.removeEventListener("mousedown", onMouseDown)
  }, [open])

  if (!finding.assetId || !allowed) return null

  // Only offer scopes whose matching key exists — a carve-out must match on
  // something concrete, never on the asset alone.
  const options = [
    { id: "rule" as const, label: SCOPE_LABEL.rule, disabled: !ruleKey },
    { id: "file" as const, label: SCOPE_LABEL.file, disabled: !fileKey },
  ]
  const enabledScopes = options.filter((o) => !o.disabled)

  const activeKey = scope === "rule" ? ruleKey : fileKey
  const canSubmit = Boolean(statement.trim()) && Boolean(activeKey) && !submitting

  async function handleConfirm() {
    if (!canSubmit) return
    setSubmitting(true)
    setError(null)
    const result = await createAcceptedRisk({
      asset_id: finding.assetId ?? null,
      source_connection_id: null,
      statement: statement.trim(),
      rule_id: scope === "rule" ? ruleKey : null,
      path_glob: scope === "file" ? fileKey : null,
      enabled: true,
    })
    setSubmitting(false)
    if (result.ok) {
      setDone(true)
      setCreatedId(result.data.acceptedRisk.id)
      setOpen(false)
      setStatement("")
    } else {
      setError(result.error)
    }
  }

  // Undo the accept by deleting the carve-out we just created. This is the only
  // faithful reversal — the finding's state never changed, a carve-out was added.
  async function handleUndo() {
    if (createdId == null || undoing) return
    setUndoing(true)
    setError(null)
    const result = await deleteAcceptedRisk(createdId)
    setUndoing(false)
    if (result.ok) {
      setDone(false)
      setCreatedId(null)
    } else {
      setError(result.error)
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape") {
      e.stopPropagation()
      setOpen(false)
      triggerRef.current?.focus()
    }
  }

  return (
    <div ref={rootRef} className="relative">
      {done ? (
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 text-xs font-medium text-[var(--color-text-secondary)]">
            <svg className="h-3.5 w-3.5 text-[var(--color-state-fixed-text)]" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
              <path d="M3.5 8.5l3 3 6-7" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            Risk accepted
          </span>
          <Button variant="ghost" size="sm" onClick={handleUndo} isLoading={undoing} aria-label="Undo accepting this risk">
            Undo
          </Button>
          {error && (
            <span role="alert" className="text-[11px] text-[var(--color-severity-high-text)]">{error}</span>
          )}
        </div>
      ) : (
        <Button
          ref={triggerRef}
          variant="secondary"
          size="sm"
          onClick={() => setOpen((v) => !v)}
          aria-haspopup="dialog"
          aria-expanded={open}
        >
          Accept risk
        </Button>
      )}

      {open && !done && (
        <div
          role="dialog"
          aria-label="Accept as intended risk"
          onKeyDown={handleKeyDown}
          className="absolute left-0 top-full z-50 mt-1 w-[min(22rem,calc(100vw-2rem))] space-y-3 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-3 shadow-[var(--shadow-card)]"
        >
          <p className="text-xs leading-relaxed text-[var(--color-text-tertiary)]">
            Declare this behavior as intended-by-design. Matching findings will be ruled out on
            the next scan.
          </p>
          <Textarea
            value={statement}
            onChange={(e) => setStatement(e.target.value)}
            placeholder="e.g. eval() here is a sandboxed plugin loader"
            aria-label="Why this is intended"
          />
          <div className="space-y-1.5">
            <p className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
              Apply exception to
            </p>
            {enabledScopes.length > 1 ? (
              <SegmentedControl
                options={options}
                value={scope}
                onChange={setScope}
                ariaLabel="How wide the exception reaches"
              />
            ) : enabledScopes.length === 1 ? (
              <p className="text-xs text-[var(--color-text-secondary)]">
                {SCOPE_LABEL[enabledScopes[0].id]}
                <span className="text-[var(--color-text-tertiary)]"> — the only scope this finding supports</span>
              </p>
            ) : (
              <p className="text-xs text-[var(--color-severity-high-text)]">
                This finding has no rule or file to scope to, so it can’t be accepted as a risk here.
              </p>
            )}
          </div>
          {error ? (
            <p role="alert" className="text-sm text-[var(--color-severity-critical)]">
              {error}
            </p>
          ) : null}
          <div className="flex items-center justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={() => { setOpen(false); setError(null) }}>
              Cancel
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={handleConfirm}
              disabled={!canSubmit}
              isLoading={submitting}
            >
              Accept risk
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
