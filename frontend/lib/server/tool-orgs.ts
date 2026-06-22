import { getAppConfigEnvValue } from "@/lib/server/app-config"
import { getOrgsForCategories } from "@/lib/server/source-connections"

type ToolKey = "dependencies_scanning" | "code_scanning" | "secret_scanning" | "container_scanning"

const TOOL_CATEGORIES: Record<ToolKey, string[]> = {
  secret_scanning: ["code-repositories"],
  dependencies_scanning: ["code-repositories"],
  code_scanning: ["code-repositories"],
  container_scanning: ["container-registry"],
}

const TOOL_ENV_PREFIX: Record<ToolKey, string> = {
  secret_scanning: "SECRETS",
  dependencies_scanning: "Dependencies",
  code_scanning: "Code",
  container_scanning: "CONTAINER_SCANNING",
}

function parseOrgList(raw: string) {
  const byKey = new Map<string, string>()
  for (const item of raw.split(",")) {
    const trimmed = item.trim()
    if (!trimmed) continue
    const key = trimmed.toLowerCase()
    if (!byKey.has(key)) byKey.set(key, trimmed)
  }
  return Array.from(byKey.values())
}

export async function getToolEnabledOrgs(tool: ToolKey) {
  const managed = await getOrgsForCategories(TOOL_CATEGORIES[tool])
  if (!managed.length) return []

  const prefix = TOOL_ENV_PREFIX[tool]
  const scope = (getAppConfigEnvValue(`${prefix}_ORG_SCOPE`) || "all").toLowerCase()
  if (scope !== "selected") return managed

  const selected = parseOrgList(getAppConfigEnvValue(`${prefix}_ORGS`))
  if (!selected.length) return []

  const selectedKeys = new Set(selected.map((value) => value.toLowerCase()))
  return managed.filter((value) => selectedKeys.has(value.toLowerCase()))
}
