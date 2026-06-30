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
  const [error, setError] = useState(false)

  useEffect(() => {
    let active = true
    listSavedViews("findings")
      .then((rows) => { if (active) { setViews(rows); setError(false) } })
      .catch((err) => {
        if (active) {
          console.error("Failed to load saved views", err)
          setError(true)
        }
      })
    return () => { active = false }
  }, [refreshSignal])

  if (error) {
    return (
      <span className="text-2xs text-[var(--color-text-secondary)]">Couldn't load saved views</span>
    )
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
      <option value="">Views</option>
      {views.map((v) => (
        <option key={v.id} value={v.id}>{v.is_default ? `★ ${v.name}` : v.name}</option>
      ))}
    </Select>
  )
}
