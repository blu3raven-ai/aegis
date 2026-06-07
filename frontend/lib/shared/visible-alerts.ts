import type { DependenciesFinding } from "@/lib/shared/dependencies/types"

export function visibleFindingKey(alert: DependenciesFinding) {
  return [
    alert.repository.full_name.toLowerCase(),
    alert.dependency.package.ecosystem.toLowerCase(),
    alert.dependency.package.name.toLowerCase(),
    alert.security_advisory.ghsa_id,
    alert.state,
    alert.security_vulnerability.first_patched_version?.identifier ?? "",
    alert.current_version ?? "",
  ].join("::")
}

export function dedupeVisibleFindings(findings: DependenciesFinding[]) {
  const deduped = new Map<string, DependenciesFinding>()

  for (const alert of findings) {
    const key = visibleFindingKey(alert)
    const existing = deduped.get(key)

    if (!existing) {
      deduped.set(key, alert)
      continue
    }

    if (new Date(alert.created_at).getTime() > new Date(existing.created_at).getTime()) {
      deduped.set(key, alert)
    }
  }

  return Array.from(deduped.values())
}
