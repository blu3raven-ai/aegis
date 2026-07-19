"use client"

import { useState, useEffect } from "react"
import { plural } from "@/lib/shared/plural"
import type { OrganisationTeam, ResourceSharingIndex } from "./team-types"
import { TeamImagesTab } from "./TeamImagesTab"
import { TeamRepositoriesTab } from "./TeamRepositoriesTab"
import { deleteOrganisationTeam, updateOrganisationTeam } from "@/lib/client/settings-api"
import { Dialog } from "@/components/layout/Dialog"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"
import { NavTabs } from "@/components/ui/NavTabs"
import { Textarea } from "@/components/ui/Textarea"

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

  const repoCount = team.assets.filter((a) => a.type === "repo").length
  const imageCount = team.assets.filter((a) => a.type === "image").length

  return (
    <Card as="section" className="min-w-0 flex-1">
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
            <FormField
              label="Team Name"
              htmlFor="team-name"
              error={error}
            >
              <Input
                id="team-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Platform Team"
                autoFocus
                invalid={!!error && !name.trim()}
              />
            </FormField>
            <FormField label="Description" htmlFor="team-description">
              <Textarea
                id="team-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={2}
                className="resize-none"
                placeholder="What does this team do?"
              />
            </FormField>
            <div className="flex gap-2">
              <Button
                variant="primary"
                size="sm"
                onClick={handleSave}
                disabled={submitting}
                isLoading={submitting}
              >
                {submitting ? "Saving…" : "Save Changes"}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  setIsEditing(false)
                  setName(team.name)
                  setDescription(team.description)
                  setError(null)
                }}
                disabled={submitting}
              >
                Cancel
              </Button>
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
                  <Button
                    variant="ghost"
                    size="sm"
                    iconOnly
                    onClick={() => setIsEditing(true)}
                    aria-label="Edit team details"
                  >
                    {ICON_PEN}
                  </Button>
                  {team.source !== "github" && (
                    <Button
                      variant="ghost"
                      size="sm"
                      iconOnly
                      onClick={() => setShowDeleteDialog(true)}
                      disabled={submitting}
                      aria-label="Delete team"
                      className="text-[var(--color-severity-critical-text)] hover:bg-[var(--color-severity-critical-subtle)] hover:text-[var(--color-severity-critical-text)]"
                    >
                      {ICON_TRASH}
                    </Button>
                  )}
                </div>
              )}
            </div>
            <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
              {team.description || "No description yet."}
            </p>
          </>
        )}
        <div className="mt-3 flex flex-wrap gap-x-4 gap-y-2 font-mono text-[11px] font-medium uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
          <span>{team.members.length} {plural(team.members.length, "member")}</span>
          <span>{repoCount} {plural(repoCount, "repo")}</span>
          <span>{imageCount} {plural(imageCount, "image")}</span>
        </div>
      </div>

      <NavTabs
        ariaLabel="Team configuration"
        tabs={[
          { id: "repositories", label: "Repositories" },
          { id: "images", label: "Container Registry" },
        ]}
        activeTab={tab}
        onChange={setTab}
        containerClassName="mt-6 bg-transparent px-0"
      />

      <div className="mt-6">
        {tab === "repositories" && (
          <TeamRepositoriesTab team={team} sharing={sharing} canEdit={canEdit} onChanged={onChanged} />
        )}
        {tab === "images" && (
          <TeamImagesTab team={team} sharing={sharing} canEdit={canEdit} onChanged={onChanged} />
        )}
      </div>

      <div className="mt-10 rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-4 py-3">
        <h4 className="text-xs font-semibold text-[var(--color-text-primary)]">Sharing &amp; role precedence</h4>
        <p className="mt-1 text-xs text-[var(--color-text-secondary)] leading-relaxed">
          Resources can be shared with multiple teams. Users get their strongest matching team role for
          shared resources.
        </p>
      </div>
    </Card>
  )
}
