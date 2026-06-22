"use client"

import { useState } from "react"
import { createOrganisationTeam } from "@/lib/client/settings-api"
import { Button } from "@/components/ui/Button"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"
import { Sheet } from "@/components/ui/Sheet"
import { Textarea } from "@/components/ui/Textarea"

interface CreateTeamPanelProps {
  open: boolean
  onClose: () => void
  onCreated: () => Promise<void>
}

export function CreateTeamPanel({ open, onClose, onCreated }: CreateTeamPanelProps) {
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault()
    setSubmitting(true)
    setError(null)

    const result = await createOrganisationTeam({ name, description })
    if (result.ok) {
      setName("")
      setDescription("")
      await onCreated()
      onClose()
    } else {
      setError(result.error)
    }
    setSubmitting(false)
  }

  function handleClose() {
    onClose()
    setError(null)
  }

  return (
    <Sheet
      open={open}
      onClose={handleClose}
      title="Create team"
      description="Set up a team first, then assign members, repositories, and container images from the editor."
      size="md"
      dismissGuard={{ isDirty: name.trim() !== "" || description.trim() !== "" }}
      footer={
        <div className="flex justify-end gap-2">
          <Button variant="ghost" size="md" onClick={handleClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            form="create-team-form"
            variant="primary"
            size="md"
            disabled={submitting}
            isLoading={submitting}
          >
            {submitting ? "Creating…" : "Create team"}
          </Button>
        </div>
      }
    >
      <form id="create-team-form" onSubmit={onSubmit} className="space-y-4">
        <FormField label="Team name" htmlFor="create-team-name" required>
          <Input
            id="create-team-name"
            required
            value={name}
            onChange={(event) => setName(event.target.value)}
            autoFocus
            placeholder="Platform"
          />
        </FormField>
        <FormField label="Description" htmlFor="create-team-description">
          <Textarea
            id="create-team-description"
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            rows={3}
            placeholder="Owns the shared application platform and supporting services."
          />
        </FormField>
        {error && (
          <p
            role="alert"
            className="rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-3 py-2 text-sm text-[var(--color-severity-critical)]"
          >
            {error}
          </p>
        )}
      </form>
    </Sheet>
  )
}
