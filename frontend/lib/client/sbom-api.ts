import { apiClient } from "./api-client.ts"

export type SbomFormat = "cyclonedx-json" | "cyclonedx-xml" | "spdx-json" | "spdx-tag-value"

export interface SbomHistoryEntry {
  manifest_set_hash: string
  created_at: string
  blob_pointer: string
}

export interface CycloneDxComponent {
  name: string
  version: string
  type: string
  purl?: string
  licenses?: Array<{ license: { id: string } }>
  hashes?: Array<{ alg: string; content: string }>
}

export interface ParsedSbom {
  metadata?: { timestamp?: string; tools?: unknown[] }
  components: CycloneDxComponent[]
  dependencies: Array<{ ref: string; dependsOn?: string[] }>
}

export async function fetchSbomHistory(repoId: string, limit?: number): Promise<SbomHistoryEntry[]> {
  const qs = new URLSearchParams()
  if (limit != null) qs.set("limit", String(limit))
  const query = qs.toString() ? `?${qs.toString()}` : ""
  const data = await apiClient<SbomHistoryEntry[] | { items: SbomHistoryEntry[] }>(
    `/api/v1/sboms/repo/${encodeURIComponent(repoId)}/history${query}`,
  )
  return Array.isArray(data) ? data : (data as { items: SbomHistoryEntry[] }).items ?? []
}

export async function fetchSbom(params: {
  repoId?: string
  imageDigest?: string
  format?: SbomFormat
}): Promise<string> {
  const { repoId, imageDigest, format = "cyclonedx-json" } = params
  const qs = new URLSearchParams({ format })

  if (repoId) {
    return apiClient<string>(`/api/v1/sboms/repo/${encodeURIComponent(repoId)}?${qs.toString()}`)
  }
  if (imageDigest) {
    return apiClient<string>(`/api/v1/sboms/image/${encodeURIComponent(imageDigest)}?${qs.toString()}`)
  }
  throw new Error("sbom-api: either repoId or imageDigest is required")
}

export function parseCycloneDxJson(text: string): ParsedSbom {
  let raw: unknown
  try {
    raw = JSON.parse(text)
  } catch {
    throw new Error("sbom-api: invalid JSON in SBOM payload")
  }

  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { components: [], dependencies: [] }
  }

  const obj = raw as Record<string, unknown>

  const components: CycloneDxComponent[] = []
  if (Array.isArray(obj["components"])) {
    for (const c of obj["components"] as unknown[]) {
      if (typeof c !== "object" || c === null) continue
      const comp = c as Record<string, unknown>
      components.push({
        name: String(comp["name"] ?? ""),
        version: String(comp["version"] ?? ""),
        type: String(comp["type"] ?? "library"),
        purl: comp["purl"] != null ? String(comp["purl"]) : undefined,
        licenses: Array.isArray(comp["licenses"])
          ? (comp["licenses"] as unknown[]).filter(
              (l): l is { license: { id: string } } =>
                typeof l === "object" &&
                l !== null &&
                "license" in l &&
                typeof (l as { license: unknown }).license === "object" &&
                (l as { license: unknown }).license !== null,
            )
          : undefined,
        hashes: Array.isArray(comp["hashes"])
          ? (comp["hashes"] as unknown[]).filter(
              (h): h is { alg: string; content: string } =>
                typeof h === "object" && h !== null && "alg" in h && "content" in h,
            )
          : undefined,
      })
    }
  }

  const dependencies: Array<{ ref: string; dependsOn?: string[] }> = []
  if (Array.isArray(obj["dependencies"])) {
    for (const d of obj["dependencies"] as unknown[]) {
      if (typeof d !== "object" || d === null) continue
      const dep = d as Record<string, unknown>
      dependencies.push({
        ref: String(dep["ref"] ?? ""),
        dependsOn: Array.isArray(dep["dependsOn"])
          ? (dep["dependsOn"] as unknown[]).map(String)
          : undefined,
      })
    }
  }

  const metaRaw = obj["metadata"]
  const metadata =
    typeof metaRaw === "object" && metaRaw !== null
      ? {
          timestamp:
            typeof (metaRaw as Record<string, unknown>)["timestamp"] === "string"
              ? String((metaRaw as Record<string, unknown>)["timestamp"])
              : undefined,
          tools: Array.isArray((metaRaw as Record<string, unknown>)["tools"])
            ? ((metaRaw as Record<string, unknown>)["tools"] as unknown[])
            : undefined,
        }
      : undefined

  return { metadata, components, dependencies }
}
