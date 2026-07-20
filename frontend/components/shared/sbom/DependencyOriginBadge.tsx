import type { DependencyOrigin } from "@/lib/client/sbom-api"

const META: Record<DependencyOrigin, { label: string; tone: string; tooltip: string }> = {
  direct: {
    label: "Direct",
    tone: "border-[var(--color-accent)]/30 bg-[var(--color-accent-subtle)] text-[var(--color-accent)]",
    tooltip: "Declared in the project manifest. Fix or upgrade it here.",
  },
  transitive: {
    label: "Transitive",
    tone: "border-[var(--color-border)] bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]",
    tooltip: "Pulled in by another dependency. Remediate via the parent.",
  },
  unknown: {
    label: "Unknown",
    tone: "border-[var(--color-border)] bg-transparent text-[var(--color-text-tertiary)]",
    tooltip: "Origin couldn't be determined. The SBOM has no dependency graph.",
  },
}

/** Direct / transitive / unknown dependency origin. `unknown` is the honest
 * default when the SBOM carries no dependency graph (flat syft list, OS pkgs). */
export function DependencyOriginBadge({ origin }: { origin: DependencyOrigin }) {
  const meta = META[origin]
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-px text-2xs font-semibold ${meta.tone}`}
      title={meta.tooltip}
    >
      {meta.label}
    </span>
  )
}
