"use client"

import { useState } from "react"
import { addOrganisationContainerImage, removeOrganisationContainerImage, searchOrganisationContainerImages } from "@/lib/client/settings-api"
import { Button } from "@/components/ui/Button"
import type { OrganisationTeam, ResourceSharingIndex } from "./team-types"
import { ResourceAutocomplete } from "./ResourceAutocomplete"

interface TeamImagesTabProps {
  team: OrganisationTeam
  sharing: ResourceSharingIndex
  canEdit: boolean
  onChanged: () => Promise<void>
}

export function TeamImagesTab({ team, sharing, canEdit, onChanged }: TeamImagesTabProps) {
  const [value, setValue] = useState("")
  const [suggestions, setSuggestions] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  const imageAssets = team.assets.filter((a) => a.type === "image")

  async function updateValue(next: string) {
    setValue(next)
    try {
      const result = await searchOrganisationContainerImages(null, next)
      setSuggestions(result.images.map((image) => image.image))
      setError(result.error ?? null)
    } catch {
      setSuggestions([])
      setError("Could not load image suggestions. You can still enter the image path manually.")
    }
  }

  async function addImage(input = value) {
    const trimmed = input.trim()
    if (!trimmed) return
    setSubmitting(true)
    const result = await addOrganisationContainerImage(team.id, trimmed)
    if (result.ok) {
      setValue("")
      setSuggestions([])
      setError(null)
      await onChanged()
    } else {
      setError(result.error)
    }
    setSubmitting(false)
  }

  async function removeImage(assetId: string) {
    const result = await removeOrganisationContainerImage(team.id, assetId)
    if (result.ok) {
      await onChanged()
    } else {
      setError(result.error)
    }
  }

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        {imageAssets.map((asset) => {
          const sharedTeamCount = sharing[asset.assetId]?.length ?? 0
          return (
            <div key={asset.assetId} className="flex items-center justify-between gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)]/50 p-3">
              <div className="flex flex-1 items-center gap-2 min-w-0">
                <span className="font-mono text-sm text-[var(--color-text-primary)] truncate">{asset.displayName}</span>
                {sharedTeamCount > 1 && (
                  <span className="rounded bg-[var(--color-state-pending-subtle)] px-2 py-0.5 text-[11px] font-medium text-[var(--color-state-pending-text)] whitespace-nowrap">
                    shared with {sharedTeamCount} teams
                  </span>
                )}
              </div>
              <Button
                disabled={!canEdit}
                variant="secondary"
                size="sm"
                onClick={() => void removeImage(asset.assetId)}
                className="border-[var(--color-severity-critical-border)] bg-transparent text-[var(--color-severity-critical-text)] hover:border-[var(--color-severity-critical-border)] hover:bg-[var(--color-severity-critical-subtle)] hover:text-[var(--color-severity-critical-text)]"
              >
                Remove
              </Button>
            </div>
          )
        })}
        {imageAssets.length === 0 && (
          <p className="py-4 text-center text-xs text-[var(--color-text-secondary)] italic">No container images assigned to this team.</p>
        )}
      </div>

      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4">
        <h4 className="text-2xs font-bold uppercase tracking-[0.14em] text-[var(--color-text-secondary)] mb-3">Add image</h4>
        <div className="space-y-3">
          <ResourceAutocomplete
            value={value}
            placeholder="Search or enter registry/org/image"
            suggestions={suggestions}
            error={error}
            onChange={(next) => void updateValue(next)}
            onPick={(next) => void addImage(next)}
          />
          <Button
            variant="primary"
            size="md"
            disabled={!canEdit || !value.trim() || submitting}
            onClick={() => void addImage()}
            isLoading={submitting}
            className="w-full"
          >
            {submitting ? "Adding..." : "Add image"}
          </Button>
        </div>
      </div>
    </div>
  )
}
