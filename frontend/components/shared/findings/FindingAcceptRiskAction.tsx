"use client"

import { useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/Button"
import { Textarea } from "@/components/ui/Textarea"
import { SegmentedControl } from "@/components/ui/SegmentedControl"
import { useHasPermission } from "@/lib/client/use-permission"
import { createAcceptedRisk } from "@/lib/client/accepted-risks-api"
import type { FindingRow } from "@/lib/shared/findings/row-mapper"

type Scope = "rule" | "file"

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
    { id: "rule" as const, label: "This rule on this repo", disabled: !ruleKey },
    { id: "file" as const, label: "This file", disabled: !fileKey },
  ]

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
      setOpen(false)
      setStatement("")
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
      <Button
        ref={triggerRef}
        variant="secondary"
        size="sm"
        onClick={() => setOpen((v) => !v)}
        disabled={done}
        aria-haspopup="dialog"
        aria-expanded={open}
      >
        {done ? "Risk accepted" : "Accept risk"}
      </Button>

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
          <SegmentedControl
            options={options}
            value={scope}
            onChange={setScope}
            ariaLabel="Carve-out scope"
          />
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
