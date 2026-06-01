const SCANNER_LABELS: Record<string, string> = {
  dependencies: "deps",
  sast: "sast",
  secrets: "secrets",
  containers: "containers",
  code_scanning: "code",
  container_scanning: "containers",
}

function chip(type: string) {
  return SCANNER_LABELS[type] ?? type
}

export function ScannerTypesBadgeList({ types }: { types: string[] }) {
  if (types.length === 0) {
    return <span className="text-xs text-[var(--color-text-tertiary)]">—</span>
  }
  return (
    <span className="flex flex-wrap gap-1">
      {types.map((t) => (
        <span
          key={t}
          className="inline-flex items-center rounded-full border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-2 py-px font-mono text-2xs text-[var(--color-text-secondary)]"
        >
          {chip(t)}
        </span>
      ))}
    </span>
  )
}
