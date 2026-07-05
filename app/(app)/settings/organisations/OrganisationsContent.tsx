"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import { listOrganisationTeams } from "@/lib/client/settings-api"
import type { OrganisationTeam, ResourceSharingIndex } from "./team-types"
import { CreateTeamPanel } from "./CreateTeamPanel"
import { TeamList } from "./TeamList"
import { TeamEditor } from "./TeamEditor"

export function OrganisationsContent({ canEdit = true }: { canEdit?: boolean }) {
  const [teams, setTeams] = useState<OrganisationTeam[]>([])
  const [sharing, setSharing] = useState<ResourceSharingIndex>({ repositories: {}, containerImages: {} })
  const [selectedTeamId, setSelectedTeamId] = useState<string | null>(null)
  const [query, setQuery] = useState("")
  const [showCreate, setShowCreate] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const loadTeams = useCallback(async () => {
    // Only show the full-page loading state if we don't have any teams yet.
    // This prevents the UI from unmounting and flickering during background refreshes.
    setLoading((prev) => (teams.length === 0 ? true : prev))
    
    const result = await listOrganisationTeams()
    if (result.ok) {
      setTeams(result.teams)
      setSharing(result.sharing)
      setSelectedTeamId((current) => {
        if (!current) return result.teams[0]?.id ?? null
        const exists = result.teams.some((t) => t.id === current)
        return exists ? current : (result.teams[0]?.id ?? null)
      })
      setError(null)
    } else {
      setError(result.error)
    }
    setLoading(false)
  }, [teams.length])

  useEffect(() => {
    void loadTeams()
  }, [loadTeams])

  const selectedTeam = useMemo(
    () => teams.find((team) => team.id === selectedTeamId) ?? teams[0] ?? null,
    [selectedTeamId, teams],
  )

  const showLoading = loading && teams.length === 0
  const showEmpty = !loading && teams.length === 0

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
            Teams
          </h2>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
            Create teams and attach repositories and container images.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowCreate(true)}
          disabled={!canEdit}
          className="flex items-center gap-2 rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-bg)] disabled:cursor-not-allowed disabled:opacity-50"
        >
          <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <line x1="12" y1="5" x2="12" y2="19"></line>
            <line x1="5" y1="12" x2="19" y2="12"></line>
          </svg>
          New Team
        </button>
      </div>

      {error && <p className="rounded-lg border border-[var(--color-severity-critical)]/20 bg-[var(--color-severity-critical)]/10 px-3 py-2 text-sm text-[var(--color-severity-critical)]">{error}</p>}

      {showLoading ? (
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-6 text-sm text-[var(--color-text-secondary)]">Loading teams...</div>
      ) : showEmpty ? (
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-6 text-sm text-[var(--color-text-secondary)]">
          No teams yet. Create your first team to start grouping members and access.
        </div>
      ) : (
        <div className="flex flex-col gap-6 md:min-h-[calc(100vh-12rem)] md:flex-row md:items-start">
          <TeamList teams={teams} selectedTeamId={selectedTeam?.id ?? null} query={query} onQueryChange={setQuery} onSelect={setSelectedTeamId} />
          {selectedTeam && <TeamEditor team={selectedTeam} sharing={sharing} canEdit={canEdit} onChanged={loadTeams} />}
        </div>
      )}

      <CreateTeamPanel open={showCreate} onClose={() => setShowCreate(false)} onCreated={loadTeams} />
    </div>
  )
}
