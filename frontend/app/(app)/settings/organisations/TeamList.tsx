"use client"

import { SearchInput } from "@/components/shared/SearchInput"
import { plural } from "@/lib/shared/plural"
import type { OrganisationTeam } from "./team-types"

interface TeamListProps {
  teams: OrganisationTeam[]
  selectedTeamId: string | null
  query: string
  onQueryChange: (query: string) => void
  onSelect: (teamId: string) => void
}

export function TeamList({ teams, selectedTeamId, query, onQueryChange, onSelect }: TeamListProps) {
  const filtered = teams.filter((team) => team.name.toLowerCase().includes(query.toLowerCase()))

  return (
    <div className="w-full shrink-0 space-y-4 md:sticky md:top-6 md:w-72 md:self-start lg:w-80">
      <SearchInput
        value={query}
        onChange={onQueryChange}
        placeholder="Search teams…"
        ariaLabel="Search teams"
      />

      <div className="space-y-1 md:max-h-[calc(100vh-12rem)] md:overflow-y-auto md:pr-2">
        {filtered.map((team) => (
          <button
            key={team.id}
            onClick={() => onSelect(team.id)}
            className={`block w-full rounded-md px-3 py-2.5 text-left transition-colors ${
              selectedTeamId === team.id
                ? "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
                : "text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
            }`}
          >
            <div className="truncate font-medium">{team.name}</div>
            <div className="mt-0.5 truncate text-[11px] opacity-70">
              {team.members.length} {plural(team.members.length, "member")} · {team.assets.filter((a) => a.type === "repo").length} {plural(team.assets.filter((a) => a.type === "repo").length, "repo")}
            </div>
          </button>
        ))}
        {filtered.length === 0 && <p className="px-3 py-4 text-center text-xs text-[var(--color-text-secondary)]">No teams match your search.</p>}
      </div>
    </div>
  )
}
