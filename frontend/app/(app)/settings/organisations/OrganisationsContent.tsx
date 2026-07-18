"use client"

import { useCallback, useEffect, useMemo, useState, type MutableRefObject } from "react"
import { listOrganisationTeams } from "@/lib/client/settings-api"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import type { OrganisationTeam, ResourceSharingIndex } from "./team-types"
import { CreateTeamPanel } from "./CreateTeamPanel"
import { TeamList } from "./TeamList"
import { TeamEditor } from "./TeamEditor"

interface OrganisationsContentProps {
  canEdit?: boolean
  /**
   * When provided, the form skips its in-content "New Team" button and
   * publishes the open-create handler to this ref so the parent section can
   * mount the action in its header.
   */
  createTriggerRef?: MutableRefObject<(() => void) | null>
}

export function OrganisationsContent({ canEdit = true, createTriggerRef }: OrganisationsContentProps) {
  const [teams, setTeams] = useState<OrganisationTeam[]>([])
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

  useEffect(() => {
    if (!createTriggerRef) return
    createTriggerRef.current = () => setShowCreate(true)
    return () => {
      createTriggerRef.current = null
    }
  }, [createTriggerRef])

  const selectedTeam = useMemo(
    () => teams.find((team) => team.id === selectedTeamId) ?? teams[0] ?? null,
    [selectedTeamId, teams],
  )

  /** Derived index: assetId → list of teams holding that asset. Used to flag
   *  resources shared across multiple teams in the per-team scope tabs. */
  const sharing = useMemo<ResourceSharingIndex>(() => {
    const index: ResourceSharingIndex = {}
    for (const team of teams) {
      for (const asset of team.assets) {
        if (!index[asset.assetId]) index[asset.assetId] = []
        index[asset.assetId].push(team.id)
      }
    }
    return index
  }, [teams])

  const showLoading = loading && teams.length === 0
  const showEmpty = !loading && teams.length === 0

  return (
    <div className="space-y-6">
      {/* Title + subtitle come from the parent <SettingsSection>. When the
          parent provides a createTriggerRef, the action lives in the section
          header and we skip the in-content button row. */}
      {!createTriggerRef && (
        <div className="flex items-start justify-end gap-4">
          <Button
            variant="primary"
            size="md"
            onClick={() => setShowCreate(true)}
            disabled={!canEdit}
            leadingIcon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <line x1="12" y1="5" x2="12" y2="19"></line>
                <line x1="5" y1="12" x2="19" y2="12"></line>
              </svg>
            }
          >
            New Team
          </Button>
        </div>
      )}

      {error && <p className="rounded-md border border-[var(--color-severity-critical)]/20 bg-[var(--color-severity-critical)]/10 px-3 py-2 text-sm text-[var(--color-severity-critical-text)]">{error}</p>}

      {showLoading ? (
        <Card padding="lg" className="text-sm text-[var(--color-text-secondary)]">Loading teams...</Card>
      ) : showEmpty ? (
        <div className="flex flex-col items-center justify-center rounded border border-dashed border-[var(--color-border)] bg-[var(--color-surface-raised)]/30 py-16 px-6 text-center">
          <svg className="mb-3 h-12 w-12 text-[var(--color-text-tertiary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M17 20h5v-2a3 3 0 00-5.856-1.487M7 20H2v-2a3 3 0 015.856-1.487M18 13a3 3 0 11-6 0 3 3 0 016 0m-9 0a3 3 0 11-6 0 3 3 0 016 0M13 6a4 4 0 11-8 0 4 4 0 018 0z" />
          </svg>
          <h3 className="text-base font-semibold text-[var(--color-text-primary)]">No teams yet</h3>
          <p className="mt-1 max-w-md text-sm text-[var(--color-text-secondary)]">Create your first team to start grouping members and access.</p>
          {canEdit && (
            <Button
              variant="primary"
              size="sm"
              onClick={() => setShowCreate(true)}
              className="mt-4"
              leadingIcon={
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="12" y1="5" x2="12" y2="19"></line>
                  <line x1="5" y1="12" x2="19" y2="12"></line>
                </svg>
              }
            >
              New Team
            </Button>
          )}
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
