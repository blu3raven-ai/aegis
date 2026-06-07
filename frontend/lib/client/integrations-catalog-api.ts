import { apiClient } from "./api-client.ts"

const BASE = "/api/v1/integrations"

export interface ConfigField {
  name: string
  label: string
  field_type: "text" | "url" | "password" | "select"
  required: boolean
  placeholder?: string
  options?: string[]
  secret: boolean
}

export interface ConnectorType {
  id: string
  name: string
  description: string
  category: "notifications" | "ticketing" | "cicd" | "automation" | string
  icon_slug: string
  enterprise_only: boolean
  config_fields: ConfigField[]
  docs_url: string
  // FE-only marker for roadmap placeholders that are not yet wired up
  coming_soon?: boolean
}

export interface CatalogResponse {
  connectors: ConnectorType[]
  total: number
}

export async function getCatalog(): Promise<CatalogResponse> {
  return apiClient<CatalogResponse>(`${BASE}/catalog`)
}
