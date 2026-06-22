"use client"

import { useState } from "react"

import { updateFindingAssignee } from "@/lib/client/findings-api"
import { FindingAssigneePicker } from "@/components/shared/findings/FindingAssigneePicker"

export interface FindingAssigneeEditorProps {
  findingId: string
  currentAssignee: string | null
  onUpdate: (next: string | null) => void
}

export function FindingAssigneeEditor({
  findingId,
  currentAssignee,
  onUpdate,
}: FindingAssigneeEditorProps) {
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function commit(next: string | null) {
    const numericId = Number(findingId)
    if (!Number.isFinite(numericId)) {
      setError("Invalid finding id")
      return
    }
    if ((currentAssignee ?? null) === next) return
    setSaving(true)
    setError(null)
    try {
      const result = await updateFindingAssignee(numericId, next)
      onUpdate(result.finding.assignee_user_id ?? null)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to update assignee")
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex flex-col gap-1">
      <FindingAssigneePicker
        value={currentAssignee}
        onChange={(next) => void commit(next)}
        emptyLabel="Unassigned"
        disabled={saving}
        triggerAriaLabel={currentAssignee ? `Change assignee (${currentAssignee})` : "Set assignee"}
      />
      {error && (
        <div role="alert" className="text-2xs text-[var(--color-severity-critical)]">
          {error}
        </div>
      )}
    </div>
  )
}
