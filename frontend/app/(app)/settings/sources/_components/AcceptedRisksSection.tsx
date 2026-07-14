"use client"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { FilterChip } from "@/components/ui/FilterChip"
import { SettingsCard } from "@/components/shared/SettingsCard"
import {
  listAcceptedRisks,
  createAcceptedRisk,
  deleteAcceptedRisk,
  type AcceptedRisk,
} from "@/lib/client/accepted-risks-api"

interface Props {
  connectionId: string
}

/** Accepted-risk management section for a source connection's scope config page. */
export function AcceptedRisksSection({ connectionId }: Props) {
  const [risks, setRisks] = useState<AcceptedRisk[]>([])
  const [statement, setStatement] = useState("")
  const [pathGlob, setPathGlob] = useState("")
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    listAcceptedRisks().then((result) => {
      if (result.ok) {
        setRisks(result.data.acceptedRisks.filter((r) => r.sourceConnectionId === connectionId))
      }
    })
  }, [connectionId])

  async function handleAdd() {
    if (!statement.trim()) return
    setSubmitting(true)
    setError(null)
    const result = await createAcceptedRisk({
      statement: statement.trim(),
      source_connection_id: connectionId,
      path_glob: pathGlob.trim() || null,
      enabled: true,
    })
    setSubmitting(false)
    if (result.ok) {
      setRisks((prev) => [result.data.acceptedRisk, ...prev])
      setStatement("")
      setPathGlob("")
    } else {
      setError(result.error)
    }
  }

  async function handleDelete(id: number) {
    const result = await deleteAcceptedRisk(id)
    if (result.ok) {
      setRisks((prev) => prev.filter((r) => r.id !== id))
    }
  }

  return (
    <SettingsCard
      eyebrow="Accepted risks"
      title="Accepted Risks"
      subtitle="Declare intended-by-design behavior so matching findings are ruled out."
    >
      {/* Risk list */}
      <div className="space-y-2">
        {risks.length === 0 ? (
          <p className="text-sm text-[var(--color-text-secondary)]">No accepted risks yet.</p>
        ) : (
          risks.map((risk) => (
            <div
              key={risk.id}
              className="flex items-start gap-3 rounded-lg border border-[var(--color-border)] px-4 py-3"
            >
              <div className="min-w-0 flex-1 space-y-1.5">
                <p className="text-sm text-[var(--color-text-primary)]">{risk.statement}</p>
                {(risk.pathGlob || risk.ruleId || risk.scanner) && (
                  <div className="flex flex-wrap gap-1.5">
                    {risk.pathGlob && (
                      <FilterChip
                        label={risk.pathGlob}
                        active={false}
                        onClick={() => undefined}
                        disabled
                      />
                    )}
                    {risk.ruleId && (
                      <FilterChip
                        label={risk.ruleId}
                        active={false}
                        onClick={() => undefined}
                        disabled
                      />
                    )}
                    {risk.scanner && (
                      <FilterChip
                        label={risk.scanner}
                        active={false}
                        onClick={() => undefined}
                        disabled
                      />
                    )}
                  </div>
                )}
              </div>
              <Button
                variant="ghost"
                size="xs"
                onClick={() => handleDelete(risk.id)}
                className="shrink-0 text-[var(--color-text-secondary)]"
              >
                Remove
              </Button>
            </div>
          ))
        )}
      </div>

      {/* Add form */}
      <div className="mt-4 space-y-3">
        <div className="space-y-2">
          <Input
            placeholder="Describe the accepted behavior (required)"
            value={statement}
            onChange={(e) => setStatement(e.target.value)}
            size="md"
          />
          <Input
            placeholder="Path glob, e.g. app/handlers/*.py (optional)"
            value={pathGlob}
            onChange={(e) => setPathGlob(e.target.value)}
            size="md"
          />
        </div>
        {error && (
          <p role="alert" className="text-xs text-[var(--color-severity-critical-text)]">
            {error}
          </p>
        )}
        <Button
          variant="primary"
          size="sm"
          onClick={handleAdd}
          disabled={!statement.trim() || submitting}
          isLoading={submitting}
        >
          Add
        </Button>
      </div>
    </SettingsCard>
  )
}
