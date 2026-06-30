/** Badge distinguishing a container-image SBOM source from a dependency scan. */
export function SourceBadge({ isContainer }: { isContainer: boolean }) {
  const label = isContainer ? "Container" : "Dependencies"
  const colors = isContainer
    ? "bg-[var(--color-argus-subtle)] text-[var(--color-argus)]"
    : "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
  return <span className={`inline-flex rounded-full px-2 py-0.5 text-2xs font-semibold ${colors}`}>{label}</span>
}
