"use client"

import { useState } from "react"
import { Button } from "@/components/ui/Button"
import { Textarea } from "@/components/ui/Textarea"
import { SegmentedControl } from "@/components/ui/SegmentedControl"
import { useHasPermission } from "@/lib/client/use-permission"
import { createAcceptedRisk } from "@/lib/client/accepted-risks-api"
import type { FindingRow } from "@/lib/shared/findings/row-mapper"

type Scope = "rule" | "file"

/**
 * Drawer create surface for a ground-truth carve-out. Declares the finding's
 * behavior as intended-by-design so matching findings are ruled out on the next
 * scan. The scope choice picks which key the carve-out matches on; a carve-out
 * that would match on nothing (asset only) is never submitted.
 */
export function FindingAcceptRiskAction({ finding }: { finding: FindingRow }) {
  const { allowed } = useHasPermission("manage_sources")
  const ruleKey = finding.ruleId ?? finding.rule ?? null
  const fileKey = finding.filePath ?? null
  // Default to the rule scope, falling back to file when the finding carries
  // no rule id — so the default is always a scope that can actually match.
  const [open, setOpen] = useState(false)
  const [statement, setStatement] = useState("")
  const [scope, setScope] = useState<Scope>(ruleKey ? "rule" : "file")
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)

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

  return (
    <section className="space-y-2">
      <h3 className="text-base font-semibold text-[var(--color-text-primary)]">
        Accept as intended risk
      </h3>
      <p className="text-sm text-[var(--color-text-tertiary)]">
        Declare this behavior as intended-by-design. Matching findings will be ruled out on
        the next scan.
      </p>

      {done ? (
        <p className="text-sm text-[var(--color-status-ok-text)]">
          Accepted. This finding will be ruled out on the next scan.
        </p>
      ) : !open ? (
        <Button variant="secondary" size="sm" onClick={() => setOpen(true)}>
          Accept as intended risk
        </Button>
      ) : (
        <div className="space-y-3">
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
          <div className="flex items-center gap-2">
            <Button
              variant="primary"
              size="sm"
              onClick={handleConfirm}
              disabled={!canSubmit}
              isLoading={submitting}
            >
              Accept risk
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setOpen(false)
                setError(null)
              }}
            >
              Cancel
            </Button>
          </div>
        </div>
      )}
    </section>
  )
}
