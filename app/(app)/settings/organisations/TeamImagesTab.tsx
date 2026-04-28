"use client"

import { useState } from "react"
import { addOrganisationContainerImage, removeOrganisationContainerImage, searchOrganisationContainerImages } from "@/lib/client/settings-api"
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

  async function removeImage(image: string) {
    const result = await removeOrganisationContainerImage(team.id, image)
    if (result.ok) {
      await onChanged()
    } else {
      setError(result.error)
    }
  }

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        {team.containerImages.map((image) => {
          const sharedTeamCount = sharing.containerImages[image.image]?.length ?? 0
          return (
            <div key={image.image} className="flex items-center justify-between gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)]/50 p-3">
              <div className="flex flex-1 items-center gap-2 min-w-0">
                <span className="font-mono text-sm text-[var(--color-text-primary)] truncate">{image.image}</span>
                {sharedTeamCount > 1 && (
                  <span className="rounded bg-amber-500/10 px-2 py-0.5 text-[11px] font-medium text-amber-600 whitespace-nowrap">
                    shared with {sharedTeamCount} teams
                  </span>
                )}
              </div>
              <button
                disabled={!canEdit}
                type="button"
                onClick={() => void removeImage(image.image)}
                className="rounded-lg border border-red-500/20 px-3 py-1.5 text-xs font-medium text-red-500 transition-colors hover:bg-red-500/10 disabled:opacity-40"
              >
                Remove
              </button>
            </div>
          )
        })}
        {team.containerImages.length === 0 && (
          <p className="py-4 text-center text-xs text-[var(--color-text-secondary)] italic">No container images assigned to this team.</p>
        )}
      </div>

      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4">
        <h4 className="text-[10px] font-bold uppercase tracking-wider text-[var(--color-text-secondary)] mb-3">Add image</h4>
        <div className="space-y-3">
          <ResourceAutocomplete
            value={value}
            placeholder="Search or enter registry/org/image"
            suggestions={suggestions}
            error={error}
            onChange={(next) => void updateValue(next)}
            onPick={(next) => void addImage(next)}
          />
          <button
            disabled={!canEdit || !value.trim() || submitting}
            type="button"
            onClick={() => void addImage()}
            className="w-full rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-[var(--color-accent-hover)] disabled:opacity-50"
          >
            {submitting ? "Adding..." : "Add image"}
          </button>
        </div>
      </div>
    </div>
  )
}
