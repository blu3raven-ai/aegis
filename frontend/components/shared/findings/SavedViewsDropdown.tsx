"use client"

import { useEffect, useState } from "react"
import { listSavedViews, type SavedView } from "@/lib/client/saved-views-api"
import { Select } from "@/components/ui/Select"

export interface SavedViewsDropdownProps {
  onApply: (urlState: Record<string, string>) => void
  refreshSignal?: number
}

export function SavedViewsDropdown({ onApply, refreshSignal }: SavedViewsDropdownProps) {
  const [views, setViews] = useState<SavedView[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    listSavedViews("findings")
      .then((rows) => { if (active) { setViews(rows); setError(null) } })
      .catch((err) => { if (active) setError(err instanceof Error ? err.message : String(err)) })
    return () => { active = false }
  }, [refreshSignal])

  if (error) {
    return <span className="text-2xs text-[var(--color-severity-critical)]">{error}</span>
  }

  return (
    <Select
      size="sm"
      aria-label="Saved views"
      onChange={(e) => {
        if (!e.target.value) return
        const v = views.find((view) => view.id === e.target.value)
        if (v) onApply(v.url_state)
        e.target.value = ""
      }}
      className="w-auto"
    >
      <option value="">Views ▾</option>
      {views.map((v) => (
        <option key={v.id} value={v.id}>{v.is_default ? `★ ${v.name}` : v.name}</option>
      ))}
    </Select>
  )
}
