"use client"

import { useState } from "react"
import { FindingsDrawerShell } from "@/components/shared/FindingsDrawerShell"
import { AVAILABLE_SCOPES } from "./ScopesBadgeList"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"

interface Props {
  open: boolean
  onClose: () => void
  onSubmit: (payload: { name: string; scopes: string[]; expires_in_days: number | null }) => Promise<void>
}

export function CreateApiKeyDialog({ open, onClose, onSubmit }: Props) {
  const [name, setName] = useState("")
  const [scopes, setScopes] = useState<string[]>([])
  const [expiresDays, setExpiresDays] = useState<string>("90")
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function toggleScope(value: string) {
    setScopes((prev) =>
      prev.includes(value) ? prev.filter((s) => s !== value) : [...prev, value],
    )
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) return
    setSubmitting(true)
    setError(null)
    try {
      await onSubmit({
        name: name.trim(),
        scopes,
        expires_in_days: expiresDays === "never" ? null : parseInt(expiresDays, 10),
      })
      setName("")
      setScopes([])
      setExpiresDays("90")
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create key")
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <FindingsDrawerShell open={open} onClose={onClose} label="Create API key">
      <div className="p-6">
        <h2 className="mb-4 text-base font-semibold text-[var(--color-text-primary)]">Create API key</h2>
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div>
            <label className="block mb-1 text-xs font-medium text-[var(--color-text-secondary)]">
              Name
            </label>
            <Input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. ci-pipeline-key"
              required
            />
          </div>

          <div>
            <label className="block mb-1 text-xs font-medium text-[var(--color-text-secondary)]">
              Scopes
            </label>
            <div className="flex flex-col gap-1.5">
              {AVAILABLE_SCOPES.map(({ value, label }) => (
                <label key={value} className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={scopes.includes(value)}
                    onChange={() => toggleScope(value)}
                    className="rounded border-[var(--color-border)] text-[var(--color-accent)] focus:ring-[var(--color-accent)]"
                  />
                  <span className="text-xs text-[var(--color-text-primary)]">{label}</span>
                </label>
              ))}
            </div>
          </div>

          <div>
            <label className="block mb-1 text-xs font-medium text-[var(--color-text-secondary)]">
              Expires in
            </label>
            <Select
              value={expiresDays}
              onChange={(e) => setExpiresDays(e.target.value)}
            >
              <option value="30">30 days</option>
              <option value="60">60 days</option>
              <option value="90">90 days</option>
              <option value="180">180 days</option>
              <option value="365">365 days</option>
              <option value="never">Never</option>
            </Select>
          </div>

          {error && (
            <p className="text-xs text-[var(--color-red)]">{error}</p>
          )}

          <div className="flex justify-end gap-2 pt-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={onClose}
              disabled={submitting}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              size="sm"
              disabled={submitting || !name.trim()}
              isLoading={submitting}
            >
              {submitting ? "Creating…" : "Create key"}
            </Button>
          </div>
        </form>
      </div>
    </FindingsDrawerShell>
  )
}
