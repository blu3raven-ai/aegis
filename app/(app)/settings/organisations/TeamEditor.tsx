"use client"

import { useState, useEffect } from "react"
import type { OrganisationTeam, ResourceSharingIndex } from "./team-types"
import { TeamImagesTab } from "./TeamImagesTab"
import { TeamRepositoriesTab } from "./TeamRepositoriesTab"
import { deleteOrganisationTeam, updateOrganisationTeam } from "@/lib/client/settings-api"
import { Dialog } from "@/components/layout/Dialog"

type Tab = "repositories" | "images"

interface TeamEditorProps {
  team: OrganisationTeam
  sharing: ResourceSharingIndex
  canEdit: boolean
  onChanged: () => Promise<void>
}

const ICON_PEN = (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    className="h-4 w-4"
  >
    <path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z" />
  </svg>
)

const ICON_TRASH = (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    className="h-4 w-4"
  >
    <path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M10 11v6M14 11v6" />
  </svg>
)

export function TeamEditor({ team, sharing, canEdit, onChanged }: TeamEditorProps) {
  const [tab, setTab] = useState<Tab>("repositories")
  const [isEditing, setIsEditing] = useState(false)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [name, setName] = useState(team.name)
  const [description, setDescription] = useState(team.description)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Reset internal state when team changes
  useEffect(() => {
    setName(team.name)
    setDescription(team.description)
    setIsEditing(false)
    setShowDeleteDialog(false)
    setSubmitting(false)
    setError(null)
  }, [team])

  async function handleSave() {
    if (!name.trim()) {
      setError("Team name is required")
      return
    }
    setSubmitting(true)
    setError(null)
    const result = await updateOrganisationTeam(team.id, {
      name: name.trim(),
      description: description.trim(),
    })
    if (result.ok) {
      setIsEditing(false)
      await onChanged()
    } else {
      setError(result.error)
    }
    setSubmitting(false)
  }

  async function handleDelete() {
    setShowDeleteDialog(false)
    setSubmitting(true)
    setError(null)
    const result = await deleteOrganisationTeam(team.id)
    if (result.ok) {
      await onChanged()
      // Note: setSubmitting(false) will be handled by the useEffect above
      // as team prop changes in the parent after loadTeams()
    } else {
      setError(result.error)
      setSubmitting(false)
    }
  }

  return (
    <section className="min-w-0 flex-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <Dialog
        open={showDeleteDialog}
        onClose={() => setShowDeleteDialog(false)}
        onConfirm={handleDelete}
        title="Delete Team"
        description={`Are you sure you want to permanently delete the team "${team.name}"? This action cannot be undone.`}
        confirmLabel="Delete Team"
        variant="danger"
      />
      <div className="border-b border-[var(--color-border)] pb-5">
        {isEditing ? (
          <div className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-2xs font-bold uppercase tracking-wider text-[var(--color-text-secondary)]">
                Team Name
              </label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
                placeholder="e.g. Platform Team"
                autoFocus
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-2xs font-bold uppercase tracking-wider text-[var(--color-text-secondary)]">
                Description
              </label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={2}
                className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30 resize-none"
                placeholder="What does this team do?"
              />
            </div>
            {error && <p className="text-xs text-[var(--color-severity-critical)]">{error}</p>}
            <div className="flex gap-2">
              <button
                type="button"
                onClick={handleSave}
                disabled={submitting}
                className="rounded-lg bg-[var(--color-accent)] px-3 py-1.5 text-xs font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] disabled:opacity-50"
              >
                {submitting ? "Saving..." : "Save Changes"}
              </button>
              <button
                type="button"
                onClick={() => {
                  setIsEditing(false)
                  setName(team.name)
                  setDescription(team.description)
                  setError(null)
                }}
                disabled={submitting}
                className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-primary)] transition-colors hover:bg-[var(--color-surface-raised)] disabled:opacity-50"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <>
            <div className="flex items-start justify-between gap-4">
              <div className="flex flex-1 items-center gap-3 min-w-0">
                <h2 className="text-xl font-bold text-[var(--color-text-primary)] truncate">{team.name}</h2>
                {team.source && (
                  <span className="inline-flex items-center gap-1 rounded bg-[var(--color-accent-subtle)] px-2 py-0.5 text-[11px] font-semibold text-[var(--color-accent)] whitespace-nowrap">
                    Synced from source
                  </span>
                )}
              </div>
              {canEdit && (
                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => setIsEditing(true)}
                    className="rounded-lg p-1.5 text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)] transition-colors"
                    aria-label="Edit team details"
                  >
                    {ICON_PEN}
                  </button>
                  {team.source !== "github" && (
                    <button
                      type="button"
                      onClick={() => setShowDeleteDialog(true)}
                      disabled={submitting}
                      className="rounded-lg p-1.5 text-[var(--color-severity-critical)] hover:bg-[var(--color-severity-critical-subtle)] hover:text-[var(--color-severity-critical)] transition-colors disabled:opacity-50"
                      aria-label="Delete team"
                    >
                      {ICON_TRASH}
                    </button>
                  )}
                </div>
              )}
            </div>
            <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
              {team.description || "No description yet."}
            </p>
          </>
        )}
        <div className="mt-3 flex flex-wrap gap-x-4 gap-y-2 text-[11px] font-medium uppercase tracking-wider text-[var(--color-text-secondary)]">
          <span>{team.members.length} members</span>
          <span>{team.repositories.length} repos</span>
          <span>{team.containerImages.length} images</span>
        </div>
      </div>

      <div className="mt-6 border-b border-[var(--color-border)] flex gap-1">
        <button
          type="button"
          onClick={() => setTab("repositories")}
          className={`-mb-px border-b-2 px-3 py-2.5 text-sm transition-colors ${
            tab === "repositories"
              ? "border-[var(--color-accent)] font-semibold text-[var(--color-text-primary)]"
              : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
          }`}
        >
          Repositories
        </button>
        <button
          type="button"
          onClick={() => setTab("images")}
          className={`-mb-px border-b-2 px-3 py-2.5 text-sm transition-colors ${
            tab === "images"
              ? "border-[var(--color-accent)] font-semibold text-[var(--color-text-primary)]"
              : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
          }`}
        >
          Container Registry
        </button>
      </div>

      <div className="mt-6">
        {tab === "repositories" && (
          <TeamRepositoriesTab team={team} sharing={sharing} canEdit={canEdit} onChanged={onChanged} />
        )}
        {tab === "images" && (
          <TeamImagesTab team={team} sharing={sharing} canEdit={canEdit} onChanged={onChanged} />
        )}
      </div>

      <div className="mt-10 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-4 py-3">
        <h4 className="text-xs font-semibold text-[var(--color-text-primary)]">Ownership Policy</h4>
        <p className="mt-1 text-xs text-[var(--color-text-secondary)] leading-relaxed">
          Resources can be shared with multiple teams. Users get their strongest matching team role for
          shared resources.
        </p>
      </div>
    </section>
  )
}
