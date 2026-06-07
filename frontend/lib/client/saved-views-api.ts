export interface SavedView {
  id: string
  surface: string
  name: string
  url_state: Record<string, string>
  is_default: boolean
  created_at: string | null
  updated_at: string | null
}

const BASE = "/api/v1/saved-views"

export async function listSavedViews(surface: string): Promise<SavedView[]> {
  const r = await fetch(`${BASE}?surface=${encodeURIComponent(surface)}`, { credentials: "include" })
  if (!r.ok) throw new Error(`list saved views failed: ${r.status}`)
  return r.json()
}

export async function createSavedView(input: { surface: string; name: string; url_state: Record<string, string> }): Promise<SavedView> {
  const r = await fetch(BASE, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(input),
  })
  if (!r.ok) throw new Error(`create saved view failed: ${r.status}`)
  return r.json()
}

export async function updateSavedView(id: string, patch: { name?: string; url_state?: Record<string, string> }): Promise<SavedView> {
  const r = await fetch(`${BASE}/${encodeURIComponent(id)}`, {
    method: "PATCH",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(patch),
  })
  if (!r.ok) throw new Error(`update saved view failed: ${r.status}`)
  return r.json()
}

export async function deleteSavedView(id: string): Promise<void> {
  const r = await fetch(`${BASE}/${encodeURIComponent(id)}`, {
    method: "DELETE",
    credentials: "include",
  })
  if (!r.ok) throw new Error(`delete saved view failed: ${r.status}`)
}

export async function setSavedViewDefault(id: string): Promise<SavedView> {
  const r = await fetch(`${BASE}/${encodeURIComponent(id)}`, {
    method: "PATCH",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ set_default: true }),
  })
  if (!r.ok) throw new Error(`set default failed: ${r.status}`)
  return r.json()
}
