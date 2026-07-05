/** Shared badge styles for severity and finding state across all tools. */

export const SEV_BADGE: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400",
  high:     "bg-orange-500/10 text-orange-400",
  medium:   "bg-amber-500/10 text-amber-400",
  low:      "bg-blue-500/10 text-blue-400",
}

export function sevBadgeClass(severity: string | undefined): string {
  return SEV_BADGE[(severity ?? "").toLowerCase()] ?? ""
}

export const STATE_BADGE: Record<string, { label: string; cls: string }> = {
  open:         { label: "Open",         cls: "bg-green-500/10 text-green-400" },
  deferred:     { label: "Deferred",     cls: "bg-orange-500/10 text-orange-400" },
  awaiting_fix: { label: "Awaiting Fix", cls: "bg-amber-500/10 text-amber-400" },
  fixed:        { label: "Fixed",        cls: "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]" },
  dismissed:    { label: "Dismissed",    cls: "bg-purple-500/10 text-purple-400" },
}

export function stateBadgeClass(state: string | undefined): string {
  return STATE_BADGE[(state ?? "").toLowerCase()]?.cls ?? ""
}

export function stateBadgeLabel(state: string | undefined): string {
  return STATE_BADGE[(state ?? "").toLowerCase()]?.label ?? (state ?? "")
}
