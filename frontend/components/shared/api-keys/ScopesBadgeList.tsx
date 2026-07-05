export const AVAILABLE_SCOPES = [
  { value: "read:findings", label: "Read findings" },
  { value: "write:findings", label: "Write findings" },
  { value: "read:runs", label: "Read scan runs" },
  { value: "scan:trigger", label: "Trigger scans" },
] as const

export function ScopesBadgeList({ scopes }: { scopes: string[] }) {
  if (scopes.length === 0) {
    return (
      <span className="text-[11px] text-[var(--color-text-secondary)] italic">No scopes</span>
    )
  }
  return (
    <div className="flex flex-wrap gap-1">
      {scopes.map((s) => (
        <span
          key={s}
          className="rounded px-1.5 py-0.5 text-2xs font-mono bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)] border border-[var(--color-border)]"
        >
          {s}
        </span>
      ))}
    </div>
  )
}
