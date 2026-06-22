/**
 * Four-icon row showing which scanners have run (dependencies, code, container, secrets).
 * Active scanners are highlighted; inactive are dimmed.
 */

const SCANNERS = [
  { key: "dependencies_scanning", label: "D",   title: "Dependencies (SCA)" },
  { key: "code_scanning",         label: "S",   title: "SAST (Code Scanning)" },
  { key: "container_scanning",    label: "C",   title: "Containers" },
  { key: "secret_scanning",       label: "Sec", title: "Secrets" },
] as const

interface ScannerCoverageIconsProps {
  covered: string[]
}

export function ScannerCoverageIcons({ covered }: ScannerCoverageIconsProps) {
  const coveredSet = new Set(covered)
  return (
    <div className="flex items-center gap-1">
      {SCANNERS.map(({ key, label, title }) => {
        const active = coveredSet.has(key)
        return (
          <span
            key={key}
            title={title}
            className={`inline-flex h-5 min-w-5 items-center justify-center rounded px-1 text-2xs font-semibold transition-colors ${
              active
                ? "bg-[var(--color-accent)]/15 text-[var(--color-accent)]"
                : "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)] opacity-40"
            }`}
          >
            {label}
          </span>
        )
      })}
    </div>
  )
}
