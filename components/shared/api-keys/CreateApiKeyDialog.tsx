"use client"

import { useState } from "react"
import { FindingsDrawerShell } from "@/components/shared/FindingsDrawerShell"
import { AVAILABLE_SCOPES } from "./ScopesBadgeList"

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
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. ci-pipeline-key"
              required
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]"
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
            <select
              value={expiresDays}
              onChange={(e) => setExpiresDays(e.target.value)}
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]"
            >
              <option value="30">30 days</option>
              <option value="60">60 days</option>
              <option value="90">90 days</option>
              <option value="180">180 days</option>
              <option value="365">365 days</option>
              <option value="never">Never</option>
            </select>
          </div>

          {error && (
            <p className="text-xs text-[var(--color-red)]">{error}</p>
          )}

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              disabled={submitting}
              className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || !name.trim()}
              className="rounded-lg bg-[var(--color-accent)] px-3 py-1.5 text-xs font-medium text-[var(--color-accent-on)] hover:opacity-90 transition-opacity disabled:opacity-50"
            >
              {submitting ? "Creating…" : "Create key"}
            </button>
          </div>
        </form>
      </div>
    </FindingsDrawerShell>
  )
}
