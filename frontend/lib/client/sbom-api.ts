/** Client for SBOM history and download. */

import { apiClient } from "./api-client.ts"
import { gqlFetch } from "./graphql-fetch.ts"
import { classifyLicensesRaw, type LicenseCategory } from "@/lib/sbom/license-category"

export type SbomFormat = "cyclonedx-json" | "cyclonedx-xml" | "spdx-json" | "spdx-tag-value"

export interface SbomHistoryEntry {
  run_id: string
  created_at: string | null
  key: string
}

export interface CycloneDxComponent {
  name: string
  version: string
  type: string
  purl?: string
  /** Intra-document identity used by the dependency graph (NOT the purl). */
  bomRef?: string
  /** Normalized license display strings (SPDX id, name, or expression). */
  licenses?: string[]
  /** Worst-across-licenses risk category, derived client-side from `licenses`. */
  licenseCategory?: LicenseCategory
  hashes?: Array<{ alg: string; content: string }>
}

export type DependencyOrigin = "direct" | "transitive" | "unknown"

/** Open-finding counts mapped to one component, bucketed by severity. */
export interface ComponentVulns {
  critical: number
  high: number
  medium: number
  low: number
  total: number
}

export interface ParsedSbom {
  metadata?: { timestamp?: string; tools?: unknown[]; componentRef?: string; componentType?: string }
  components: CycloneDxComponent[]
  dependencies: Array<{ ref: string; dependsOn?: string[] }>
}

// ── GraphQL transport (inlined to keep the test-time module graph tiny) ────
interface GqlSbomHistoryResponse {
  sbom: {
    history: Array<{
      runId: string
      createdAt: string | null
      key: string
    }>
  }
}

const SBOM_HISTORY_QUERY = `query SbomHistory($repo: String!, $limit: Int!) {
  sbom {
    history(repo: $repo, limit: $limit) {
      runId
      createdAt
      key
    }
  }
}`

export async function fetchSbomHistory(repoId: string, limit?: number): Promise<SbomHistoryEntry[]> {
  const data = await gqlFetch<GqlSbomHistoryResponse>("SbomHistory", SBOM_HISTORY_QUERY, {
    repo: repoId,
    limit: limit ?? 10,
  })
  return data.sbom.history.map((e) => ({
    run_id: e.runId,
    created_at: e.createdAt,
    key: e.key,
  }))
}

/** Per-ecosystem SBOM risk + coverage KPIs over the caller's full scope. */
export interface SbomEcosystemAnalytics {
  ecosystem: string
  critical: number
  high: number
  medium: number
  low: number
  totalFindings: number
  totalComponents: number
  assetsWithComponents: number
  assetsWithFindings: number
  coveragePercentage: number
  riskScore: number
}

interface GqlEcosystemAnalyticsResponse {
  sbom: {
    ecosystemAnalytics: SbomEcosystemAnalytics[]
  }
}

const SBOM_ECOSYSTEM_ANALYTICS_QUERY = `query SbomEcosystemAnalytics {
  sbom {
    ecosystemAnalytics {
      ecosystem
      critical
      high
      medium
      low
      totalFindings
      totalComponents
      assetsWithComponents
      assetsWithFindings
      coveragePercentage
      riskScore
    }
  }
}`

/** Fetch per-ecosystem risk and coverage KPIs for the caller's scope. The empty
 * ecosystem string groups findings whose package isn't in any current SBOM. */
export async function fetchSbomEcosystemAnalytics(): Promise<SbomEcosystemAnalytics[]> {
  const data = await gqlFetch<GqlEcosystemAnalyticsResponse>(
    "SbomEcosystemAnalytics",
    SBOM_ECOSYSTEM_ANALYTICS_QUERY,
    {},
  )
  return data.sbom.ecosystemAnalytics
}

interface GqlComponentVulnsResponse {
  sbom: {
    componentVulns: Array<{
      packageName: string
      packageVersion: string | null
      vulns: ComponentVulns
    }>
  }
}

const SBOM_COMPONENT_VULNS_QUERY = `query SbomComponentVulns($repo: String!) {
  sbom {
    componentVulns(repo: $repo) {
      packageName
      packageVersion
      vulns { critical high medium low total }
    }
  }
}`

/** Per-(name, version) open-finding counts for a repo. `byKey` holds version-
 * specific counts; `byName` holds the name-level bucket (findings whose source
 * didn't resolve a version), which applies to every version of that name. */
export interface ComponentVulnsLookup {
  byKey: Map<string, ComponentVulns>
  byName: Map<string, ComponentVulns>
}

const EMPTY_VULNS: ComponentVulns = { critical: 0, high: 0, medium: 0, low: 0, total: 0 }

function vulnKey(name: string, version: string): string {
  // NUL separator can't appear in a package name or version, so the key is
  // unambiguous without escaping.
  return `${name}\u0000${version}`
}

function addVulns(a: ComponentVulns, b: ComponentVulns): ComponentVulns {
  return {
    critical: a.critical + b.critical,
    high: a.high + b.high,
    medium: a.medium + b.medium,
    low: a.low + b.low,
    total: a.total + b.total,
  }
}

/** Counts for one parsed-SBOM component: the exact (name, version) bucket merged
 * with the name-level bucket. Returns undefined when neither has any findings. */
export function componentVulnsFor(
  lookup: ComponentVulnsLookup | undefined,
  name: string,
  version: string,
): ComponentVulns | undefined {
  if (!lookup) return undefined
  const exact = lookup.byKey.get(vulnKey(name, version))
  const nameLevel = lookup.byName.get(name)
  if (!exact && !nameLevel) return undefined
  return addVulns(exact ?? EMPTY_VULNS, nameLevel ?? EMPTY_VULNS)
}

/** Fetch per-(name, version) open-finding counts for a repo so callers can
 * overlay vuln badges onto the exact rows of a client-parsed SBOM. */
export async function fetchComponentVulns(repoId: string): Promise<ComponentVulnsLookup> {
  const data = await gqlFetch<GqlComponentVulnsResponse>("SbomComponentVulns", SBOM_COMPONENT_VULNS_QUERY, {
    repo: repoId,
  })
  const byKey = new Map<string, ComponentVulns>()
  const byName = new Map<string, ComponentVulns>()
  for (const entry of data.sbom.componentVulns) {
    if (entry.packageVersion) {
      byKey.set(vulnKey(entry.packageName, entry.packageVersion), entry.vulns)
    } else {
      byName.set(entry.packageName, entry.vulns)
    }
  }
  return { byKey, byName }
}

export async function fetchSbom(params: {
  repoId?: string
  imageDigest?: string
  format?: SbomFormat
  /** Repo only — a specific historical snapshot; omit for the latest. */
  runId?: string
}): Promise<string> {
  const { repoId, imageDigest, format = "cyclonedx-json", runId } = params
  const qs = new URLSearchParams({ format })
  if (runId) qs.set("run_id", runId)

  if (repoId) {
    return apiClient<string>(`/api/v1/sboms/repo/${encodeURIComponent(repoId)}?${qs.toString()}`)
  }
  if (imageDigest) {
    return apiClient<string>(`/api/v1/sboms/image/${encodeURIComponent(imageDigest)}?${qs.toString()}`)
  }
  throw new Error("sbom-api: either repoId or imageDigest is required")
}

/** Normalize a CycloneDX `licenses[]` array into display strings, keeping all
 * three shapes: `{expression}`, `{license:{id}}`, and `{license:{name}}`. */
function parseLicenses(raw: unknown): string[] {
  if (!Array.isArray(raw)) return []
  const out: string[] = []
  for (const l of raw as unknown[]) {
    if (typeof l !== "object" || l === null) continue
    const entry = l as Record<string, unknown>
    if (typeof entry["expression"] === "string" && entry["expression"].trim()) {
      out.push(entry["expression"].trim())
      continue
    }
    const lic = entry["license"]
    if (typeof lic === "object" && lic !== null) {
      const obj = lic as Record<string, unknown>
      const token =
        (typeof obj["id"] === "string" ? obj["id"] : "") ||
        (typeof obj["name"] === "string" ? obj["name"] : "")
      if (token.trim()) out.push(token.trim())
    }
  }
  return out
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
      const licenses = parseLicenses(comp["licenses"])
      // Category is computed shape-aware from the raw licenses[] (mirrors the
      // backend), so a free-text name isn't tokenized like an SPDX expression.
      const rawCat = classifyLicensesRaw(comp["licenses"])
      const licenseCategory = licenses.length ? rawCat : undefined
      components.push({
        name: String(comp["name"] ?? ""),
        version: String(comp["version"] ?? ""),
        type: String(comp["type"] ?? "library"),
        purl: comp["purl"] != null ? String(comp["purl"]) : undefined,
        bomRef: comp["bom-ref"] != null ? String(comp["bom-ref"]) : undefined,
        licenses: licenses.length ? licenses : undefined,
        licenseCategory,
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
  let metadata: ParsedSbom["metadata"]
  if (typeof metaRaw === "object" && metaRaw !== null) {
    const m = metaRaw as Record<string, unknown>
    const rootComp =
      typeof m["component"] === "object" && m["component"] !== null
        ? (m["component"] as Record<string, unknown>)
        : undefined
    metadata = {
      timestamp: typeof m["timestamp"] === "string" ? String(m["timestamp"]) : undefined,
      tools: Array.isArray(m["tools"]) ? (m["tools"] as unknown[]) : undefined,
      componentRef:
        rootComp && rootComp["bom-ref"] != null ? String(rootComp["bom-ref"]) : undefined,
      componentType:
        rootComp && rootComp["type"] != null ? String(rootComp["type"]) : undefined,
    }
  }

  return { metadata, components, dependencies }
}


/**
 * Classify each component direct/transitive/unknown by its own bom-ref — the
 * exact rule the backend uses at ingest. Direct = the root entry's dependsOn;
 * transitive = mentioned elsewhere in the graph; a component the graph never
 * mentions (orphan / partial graph) is unknown, not guessed transitive. Returns
 * a map keyed by bom-ref; components absent from the map are unknown.
 */
export function deriveDirectness(parsed: ParsedSbom): Map<string, DependencyOrigin> {
  const out = new Map<string, DependencyOrigin>()
  const rootRef = parsed.metadata?.componentRef
  const rootType = parsed.metadata?.componentType
  if (!rootRef || parsed.dependencies.length === 0) return out
  if (rootType === "container" || rootType === "operating-system") return out
  const rootEntry = parsed.dependencies.find((d) => d.ref === rootRef)
  const direct = new Set(rootEntry?.dependsOn ?? [])
  // Root absent from the graph or declaring zero direct deps gives no signal.
  if (!rootEntry || direct.size === 0) return out

  const mentioned = new Set<string>()
  for (const d of parsed.dependencies) {
    mentioned.add(d.ref)
    for (const r of d.dependsOn ?? []) mentioned.add(r)
  }
  for (const c of parsed.components) {
    if (!c.bomRef) continue
    out.set(
      c.bomRef,
      direct.has(c.bomRef) ? "direct" : mentioned.has(c.bomRef) ? "transitive" : "unknown",
    )
  }
  return out
}

/**
 * Pick the top-level refs for the dependency tree.
 *
 * Prefer the canonical CycloneDX root (`metadata.component`): its `dependsOn`
 * ARE the direct dependencies, so they head the tree — matching the Origin
 * (direct/transitive) classification shown in the components table. Fall back
 * to the heuristic — refs that are never anyone's child — only when the SBOM
 * declares no root (or the root is absent from the graph), since that
 * over-reports roots on a partial graph.
 */
export function computeDependencyRoots(
  dependencies: Array<{ ref: string; dependsOn?: string[] }>,
  rootRef?: string,
): string[] {
  if (rootRef) {
    const root = dependencies.find((dep) => dep.ref === rootRef)
    if (root) return root.dependsOn ?? []
  }

  const referencedAsChild = new Set<string>()
  for (const dep of dependencies) {
    for (const child of dep.dependsOn ?? []) referencedAsChild.add(child)
  }
  return dependencies.map((dep) => dep.ref).filter((ref) => !referencedAsChild.has(ref))
}

/** Depth past which the dependency tree stops expanding (keeps a pathological
 *  graph from rendering thousands of nested rows). */
export const MAX_TREE_DEPTH = 6

export interface DependencyTreeNode {
  ref: string
  name: string
  version: string
  children: DependencyTreeNode[]
  /** Direct dependencies that exist but weren't expanded — because this node is
   *  at the depth cap or sits on a cycle. Lets the row show it isn't a leaf. */
  hiddenCount: number
}

/**
 * Build one dependency subtree rooted at ``ref``, resolving each ref to its
 * component for name/version. Recursion stops on a cycle (``ref`` already on the
 * current path) or at ``MAX_TREE_DEPTH``; in either case the node's unexpanded
 * direct-dependency count is recorded as ``hiddenCount`` so truncation is
 * visible rather than silently rendering a node with children as a leaf.
 */
export function buildDependencyTree(
  ref: string,
  depMap: Map<string, string[]>,
  componentMap: Map<string, CycloneDxComponent>,
  visited: Set<string>,
  depth: number,
): DependencyTreeNode {
  const comp = componentMap.get(ref)
  const name = comp?.name ?? ref.split("/").pop() ?? ref
  const version = comp?.version ?? ""
  const children: DependencyTreeNode[] = []

  const potentialChildren = depMap.get(ref) ?? []
  const canExpand = !visited.has(ref) && depth < MAX_TREE_DEPTH
  if (canExpand) {
    const childVisited = new Set(visited)
    childVisited.add(ref)
    for (const childRef of potentialChildren) {
      children.push(buildDependencyTree(childRef, depMap, componentMap, childVisited, depth + 1))
    }
  }

  return { ref, name, version, children, hiddenCount: canExpand ? 0 : potentialChildren.length }
}
