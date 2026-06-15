"use client"

import { useState } from "react"
import { addOrganisationRepository, removeOrganisationRepository, searchOrganisationRepositories } from "@/lib/client/settings-api"
import { Button } from "@/components/ui/Button"
import type { OrganisationTeam, ResourceSharingIndex } from "./team-types"
import { ResourceAutocomplete } from "./ResourceAutocomplete"

interface TeamRepositoriesTabProps {
  team: OrganisationTeam
  sharing: ResourceSharingIndex
  canEdit: boolean
  onChanged: () => Promise<void>
}

export function TeamRepositoriesTab({ team, sharing, canEdit, onChanged }: TeamRepositoriesTabProps) {
  const [value, setValue] = useState("")
  const [suggestions, setSuggestions] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function updateValue(next: string) {
    setValue(next)
    try {
      const result = await searchOrganisationRepositories(null, next)
      setSuggestions(result.repositories.map((repo) => repo.fullName))
      setError(result.error ?? null)
    } catch {
      setSuggestions([])
      setError("Could not load repository suggestions. You can still enter org/repo manually.")
    }
  }

  async function addRepository(input = value) {
    const trimmed = input.trim()
    if (!trimmed) return
    setSubmitting(true)
    const result = await addOrganisationRepository(team.id, trimmed)
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

  async function removeRepository(org: string, repo: string) {
    const result = await removeOrganisationRepository(team.id, org, repo)
    if (result.ok) {
      await onChanged()
    } else {
      setError(result.error)
    }
  }

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        {team.repositories.map((repo) => {
          const key = `${repo.org}/${repo.repo}`
          const sharedTeamCount = sharing.repositories[key]?.length ?? 0
          const isGitHubSourced = repo.source === "github"

          return (
            <div key={key} className="flex items-center justify-between gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)]/50 p-3">
              <div className="flex flex-1 items-center gap-2 min-w-0">
                <span className="font-mono text-sm text-[var(--color-text-primary)] truncate">{key}</span>
                {sharedTeamCount > 1 && (
                  <span className="rounded bg-[var(--color-state-pending-subtle)] px-2 py-0.5 text-[11px] font-medium text-[var(--color-state-pending)] whitespace-nowrap">
                    shared with {sharedTeamCount} teams
                  </span>
                )}
                {isGitHubSourced && (
                  <span className="rounded bg-[var(--color-accent-subtle)] px-2 py-0.5 text-[11px] font-medium text-[var(--color-accent)] whitespace-nowrap" title="Synced from source connection">
                    Synced
                  </span>
                )}
              </div>
              <Button
                disabled={!canEdit || isGitHubSourced}
                variant="secondary"
                size="sm"
                onClick={() => void removeRepository(repo.org, repo.repo)}
                className="border-[var(--color-severity-critical-border)] bg-transparent text-[var(--color-severity-critical)] hover:border-[var(--color-severity-critical-border)] hover:bg-[var(--color-severity-critical-subtle)] hover:text-[var(--color-severity-critical)]"
                title={isGitHubSourced ? "This repository is synced from a source connection and cannot be manually removed" : undefined}
              >
                Remove
              </Button>
            </div>
          )
        })}
        {team.repositories.length === 0 && (
          <p className="py-4 text-center text-xs text-[var(--color-text-secondary)] italic">No repositories assigned to this team.</p>
        )}
      </div>

      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4">
        <h4 className="text-2xs font-bold uppercase tracking-[0.14em] text-[var(--color-text-secondary)] mb-3">Add repository</h4>
        <div className="space-y-3">
          <ResourceAutocomplete
            value={value}
            placeholder="Search or enter org/repo"
            suggestions={suggestions}
            error={error}
            onChange={(next) => void updateValue(next)}
            onPick={(next) => void addRepository(next)}
          />
          <Button
            variant="primary"
            size="md"
            disabled={!canEdit || !value.trim() || submitting}
            onClick={() => void addRepository()}
            isLoading={submitting}
            className="w-full"
          >
            {submitting ? "Adding..." : "Add repository"}
          </Button>
        </div>
      </div>
    </div>
  )
}
