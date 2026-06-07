/**
 * TypeScript client for the /api/v1/images aggregator. Mirrors the Pydantic
 * models in backend/src/images/models.py.
 */

import { apiClient } from "./api-client.ts"

export interface ImageFindingCounts {
  critical: number
  high: number
  medium: number
  low: number
}

export interface ImageRow {
  image_digest: string
  image_name: string | null
  image_tag: string | null
  first_seen_at: string
  last_scanned_at: string | null
  finding_counts: ImageFindingCounts
  repos: string[]
  layer_count: number | null
  size_bytes: number | null
  base_os: string | null
}

export interface ImageListResponse {
  images: ImageRow[]
  next_cursor: string | null
  total_count: number
}

export async function listImages(filters: {
  cursor?: string
  limit?: number
} = {}): Promise<ImageListResponse> {
  const params = new URLSearchParams()
  if (filters.cursor) params.set("cursor", filters.cursor)
  if (filters.limit != null) params.set("limit", String(filters.limit))
  const qs = params.toString()
  return apiClient<ImageListResponse>(`/api/v1/images${qs ? `?${qs}` : ""}`)
}
